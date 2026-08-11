# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **Mandatory Access Control (MAC)** на основі міток. На практиці це означає, що навіть якщо дозволи DAC, групи або можливості Linux виглядають достатніми для виконання дії, ядро все одно може заборонити її, оскільки **контексту джерела** не дозволено отримувати доступ до **цільового контексту** із запитаним класом/дозволом.<sup>[[1]](#references)</sup>

Контекст зазвичай має такий вигляд:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З погляду privesc, `type` (domain для процесів, type для об’єктів) зазвичай є найважливішим полем:<sup>[[1]](#references)</sup>

- Процес працює в **domain**, наприклад `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли та сокети мають **type**, наприклад `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Політика визначає, чи може один domain читати, записувати, виконувати або переходити до іншого

## Швидке перерахування

Якщо SELinux увімкнено, перевірте його на ранньому етапі, оскільки він може пояснити, чому поширені шляхи Linux privesc не працюють або чому привілейована обгортка навколо «нешкідливого» інструмента SELinux насправді є критично важливою:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Корисні подальші перевірки:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Цікаві знахідки:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Режим `Disabled` або `Permissive` позбавляє SELinux більшої частини його цінності як межі безпеки.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t` або явно неправильні мітки на custom paths часто вказують на неправильне маркування чи неповне розгортання.
- Локальні перевизначення у `file_contexts.local` мають пріоритет над типовими налаштуваннями policy, тому їх слід ретельно перевіряти.

## Аналіз policy

SELinux значно легше атакувати або обходити, коли ви можете відповісти на два запитання:

1. **До чого може отримати доступ мій поточний домен?**
2. **У які домени я можу перейти?**

Найкориснішими tools для цього є `sepolicy` та **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Це особливо корисно, коли на хості використовуються **ізольовані користувачі**, а не всі користувачі зіставляються з `unconfined_u`. У такому разі шукайте:<sup>[[3]](#references)</sup>

- зіставлення користувачів через `semanage login -l`
- дозволені ролі через `semanage user -l`
- доступні адміністративні домени, такі як `sysadm_t`, `secadm_t`, `webadm_t`
- записи `sudoers`, що використовують `ROLE=` або `TYPE=`

Якщо `sudo -l` містить подібні записи, SELinux є частиною межі привілеїв:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступна `newrole`:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` і `newrole` не є автоматично придатними для експлуатації, але якщо privileged wrapper або правило `sudoers` дає змогу вибрати кращу роль/тип, вони стають цінними примітивами для ескалації привілеїв.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, and High-Value Misconfigurations

Найважливіша практична відмінність між поширеними інструментами SELinux:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: тимчасова зміна мітки для певного шляху
- `semanage fcontext`: постійне правило відповідності шляху мітці
- `restorecon` / `setfiles`: повторне застосування мітки відповідно до політики/типової мітки

Це дуже важливо під час privesc, оскільки **relabeling — це не просто косметична зміна**. Воно може перетворити файл із такого, що "заблокований політикою", на такий, що "доступний для читання/виконання привілейованою confined-службою".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Перевірте локальні правила relabeling і відхилення міток від очікуваних:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Одна малопомітна, але корисна деталь: звичайний `restorecon` **не завжди повністю скасовує підозрілий label**. Якщо цільовий type входить до `customizable_types`, може знадобитися `-F`, щоб примусово виконати повне скидання. З offensive perspective це пояснює, чому незвичний `chcon` іноді може пережити поверхове очищення на кшталт «ми вже запускали restorecon».<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Високоцінні команди для пошуку в `sudo -l`, root wrappers, скриптах автоматизації або файлових capabilities:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Якщо з’являється будь-яка з можливостей MAC, також перевірте [сторінку Linux capabilities](linux-capabilities.md); документація Linux capabilities описує `cap_mac_admin` і `cap_mac_override` як специфічні для Smack, тому не слід вважати, що самі лише їхні назви обходять SELinux.<sup>[[5]](#references)</sup>

Особливо цікаві:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: постійно змінює мітку, яку має отримувати шлях
- `restorecon` / `setfiles`: повторно застосовує ці зміни у великому масштабі
- `semodule -i`: завантажує custom policy module
- `semanage permissive -a <domain_t>`: робить один домен permissive, не перемикаючи весь хост
- `setsebool -P`: назавжди змінює policy booleans
- `load_policy`: перезавантажує активну policy

Часто це **допоміжні примітиви**, а не самостійні root exploits. Їхня цінність полягає в тому, що вони дають змогу:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- зробити цільовий домен permissive
- розширити доступ між вашим доменом і захищеним типом
- повторно позначити контрольовані attacker файли так, щоб privileged service міг їх прочитати або виконати
- послабити confined service настільки, щоб наявна local bug стала експлуатованою

Приклади перевірок:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити модуль політики з правами root, ви зазвичай контролюєте межу SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Саме тому `audit2allow`, `semodule` і `semanage permissive` слід вважати чутливими адміністративними поверхнями під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюжок на робочий, не змінюючи класичні UNIX permissions.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Приховані відмови та вилучення модулів

Дуже поширена offensive-проблема — ланцюжок завершується звичайною помилкою `EACCES`, хоча очікувана відмова AVC так і не з’являється. Правила `dontaudit` можуть приховувати саме потрібний дозвіл. Якщо ви можете запустити `semodule` через `sudo` або іншу привілейовану оболонку, тимчасове вимкнення `dontaudit` може перетворити тихий збій на точну підказку щодо policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Це також корисно для перевірки того, що локальні адміністратори вже змінили. Невеликий custom module або permissive rule для одного домену часто є причиною, через яку цільовий сервіс поводиться значно менш обмежено, ніж можна було б припустити з базової policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denials часто є наступальним сигналом, а не просто захисним шумом. Вони повідомляють вам:<sup>[[1]](#references)[[15]](#references)</sup>

- до якого цільового object/type ви звернулися
- який permission було заборонено
- який domain ви наразі контролюєте
- чи зробить невелика зміна policy цей ланцюжок робочим
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Якщо локальний exploit або спроба persistence постійно завершується помилкою `EACCES` чи дивними помилками "permission denied", незважаючи на DAC permissions, які виглядають як root, зазвичай варто перевірити SELinux, перш ніж відкидати цей vector.<sup>[[1]](#references)</sup>

## Користувачі SELinux

Окрім звичайних користувачів Linux, існують користувачі SELinux. Кожен користувач Linux зіставляється з користувачем SELinux у межах policy, що дає системі змогу застосовувати різні дозволені ролі та домени до різних облікових записів.<sup>[[3]](#references)</sup>

Швидкі перевірки:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
У багатьох поширених системах користувачів зіставляють із `unconfined_u`, що зменшує практичний вплив обмеження користувачів. Однак у hardened-розгортаннях обмежені користувачі можуть зробити `sudo`, `su`, `newrole` і `runcon` набагато цікавішими, оскільки **шлях ескалації може залежати від переходу до кращої ролі/типу SELinux, а не лише від отримання UID 0**. Також пам’ятайте, що деякі обмежені користувачі взагалі не можуть викликати `sudo`/`su`, якщо policy явно не дозволяє відповідний setuid-перехід, тому хост, що використовує `staff_u` + `sysadm_r`, може перетворити, на перший погляд, незначне правило `sudo ROLE=` / `TYPE=` на справжню межу привілеїв.<sup>[[3]](#references)</sup>

## SELinux у контейнерах

Container runtimes зазвичай запускають workloads в обмеженому domain, наприклад `container_t`, і маркують container content як `container_file_t`. Якщо container process виконає escape, але все ще працюватиме з container label, записи на host усе одно можуть завершуватися помилкою, оскільки межа label залишилася чинною.<sup>[[1]](#references)[[17]](#references)</sup>

Короткий приклад:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Частина `c647,c780` — не декорація. У багатьох розгортаннях контейнерів runtime динамічно призначають категорії MCS, щоб два процеси, які працюють як `container_t`, усе одно були ізольовані один від одного. Якщо після escape ви опиняєтеся в namespace хоста, але зберігаєте початковий набір категорій, невідповідність категорій усе ще може пояснити, чому деякі шляхи хоста залишаються недоступними для читання або запису.<sup>[[17]](#references)</sup>

Сучасні операції з контейнерами, на які варто звернути увагу:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` вимикає розділення контейнерів за SELinux labels
- bind mounts із `:z` / `:Z` запускають relabeling шляху хоста для спільного/приватного використання контейнером
- широке relabeling вмісту хоста саме по собі може стати проблемою безпеки

На цій сторінці вміст про контейнери залишено стислим, щоб уникнути дублювання. Приклади зловживань і runtime-приклади, специфічні для контейнерів, дивіться тут:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Документація Red Hat: Використання SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Інструменти аналізу політик для SELinux](https://github.com/SELinuxProject/setools)
- [3] [Керування обмеженими та необмеженими користувачами — документація RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Документація Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Чому слід використовувати Multi-Category Security для контейнерів Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Документація Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
