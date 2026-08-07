# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **Mandatory Access Control (MAC)** на основі міток. На практиці це означає, що навіть якщо дозволи DAC, групи або Linux capabilities виглядають достатніми для виконання дії, kernel все одно може заборонити її, оскільки **source context** не має дозволу на доступ до **target context** із використанням запитуваного класу/дозволу.

Зазвичай context має такий вигляд:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З погляду `privesc`, поле `type` (domain для процесів, type для об’єктів) зазвичай є найважливішим:

- Процес працює в **domain**, наприклад `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли та сокети мають **type**, наприклад `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy визначає, чи може один domain читати, записувати, виконувати або переходити до іншого

## Швидке перерахування

Якщо SELinux увімкнено, перевірте його на ранньому етапі, оскільки він може пояснити, чому стандартні шляхи Linux privesc не працюють або чому привілейована обгортка навколо «нешкідливого» інструмента SELinux насправді є критично важливою:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Корисні подальші перевірки:
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
Цікаві висновки:

- Режим `Disabled` або `Permissive` усуває більшу частину цінності SELinux як межі.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t` або очевидно неправильні мітки на нестандартних шляхах часто вказують на неправильне маркування або неповне розгортання.
- Локальні перевизначення у `file_contexts.local` мають пріоритет над типовими значеннями policy, тому їх слід ретельно перевіряти.

## Аналіз policy

SELinux значно легше атакувати або обходити, коли ви можете відповісти на два запитання:

1. **До чого може отримати доступ мій поточний domain?**
2. **У які domain я можу виконати перехід?**

Найкориснішими інструментами для цього є `sepolicy` і **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Це особливо корисно, коли хост використовує **confined users**, а не зіставляє всіх із `unconfined_u`. У такому разі шукайте:<sup>[[3]](#references)</sup>

- зіставлення користувачів через `semanage login -l`
- дозволені ролі через `semanage user -l`
- доступні адміністративні домени, як-от `sysadm_t`, `secadm_t`, `webadm_t`
- записи `sudoers`, що використовують `ROLE=` або `TYPE=`

Якщо `sudo -l` містить такі записи, SELinux є частиною межі привілеїв:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступна команда `newrole`:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` і `newrole` не є автоматично експлуатованими, але якщо privileged wrapper або правило `sudoers` дозволяє вибрати роль/тип із вищими привілеями, вони стають цінними примітивами ескалації.

## Файли, перемаркування та високоризикові неправильні конфігурації

Найважливіша операційна відмінність між поширеними інструментами SELinux:<sup>[[1]](#references)</sup>

- `chcon`: тимчасова зміна мітки для певного шляху
- `semanage fcontext`: постійне правило відповідності шляху мітці
- `restorecon` / `setfiles`: повторне застосування мітки з політики/за замовчуванням

Це має велике значення під час privesc, оскільки **перемаркування — це не просто косметична зміна**. Воно може перетворити файл із такого, що "заблокований політикою", на такий, що "доступний для читання/виконання привілейованою confined-службою".

Перевірте локальні правила перемаркування та відхилення міток:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Одна тонка, але корисна деталь: звичайний `restorecon` **не завжди повністю скидає підозрілу мітку**. Якщо цільовий тип входить до `customizable_types`, може знадобитися `-F`, щоб примусово виконати повне скидання. З offensive perspective це пояснює, чому незвичний `chcon` іноді може пережити поверхневе очищення з коментарем «ми вже запустили restorecon».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Високопріоритетні команди для пошуку в `sudo -l`, root wrappers, скриптах автоматизації або file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Якщо з’являється будь-яка з MAC capabilities, додатково перевірте [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` і `cap_mac_override` трапляються рідко, але є безпосередньо релевантними, коли SELinux є частиною межі захисту.

Особливо цікаві:

- `semanage fcontext`: назавжди змінює label, який має отримати path
- `restorecon` / `setfiles`: повторно застосовують ці зміни у великому масштабі
- `semodule -i`: завантажує custom policy module
- `semanage permissive -a <domain_t>`: робить один domain permissive, не перемикаючи весь host
- `setsebool -P`: назавжди змінює policy booleans
- `load_policy`: перезавантажує активну policy

Це часто **helper primitives**, а не standalone root exploits. Їхня цінність полягає в тому, що вони дають змогу:

- зробити цільовий domain permissive
- розширити доступ між вашим domain і захищеним type
- змінити label файлів, контрольованих attacker, щоб privileged service міг їх читати або виконувати
- послабити confined service настільки, щоб наявна local bug стала exploitable

Приклади перевірок:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити модуль політики з правами root, зазвичай ви контролюєте межу SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Саме тому `audit2allow`, `semodule` і `semanage permissive` слід вважати чутливими адміністративними поверхнями під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюжок на робочий, не змінюючи класичні UNIX-дозволи.

## Приховані Denials та вилучення модулів

Дуже поширена проблема під час offensive-операцій — ланцюжок завершується загальною помилкою `EACCES`, тоді як очікуваний AVC denial не з'являється. Правила `dontaudit` можуть приховувати саме потрібний вам дозвіл. Якщо ви можете виконати `semodule` через `sudo` або іншу привілейовану обгортку, тимчасове вимкнення `dontaudit` може перетворити тихий збій на точну підказку щодо policy:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Це також корисно для перевірки того, що локальні адміністратори вже змінили. Невеликий custom module або permissive rule для одного домену часто є причиною того, що цільовий сервіс поводиться значно менш обмежено, ніж передбачає базова політика.

## Ознаки для аудиту

AVC denials часто є offensive signal, а не просто defensive noise. Вони показують:

- до якого target object/type ви звернулися
- який дозвіл було відхилено
- який domain ви наразі контролюєте
- чи дозволила б невелика зміна політики продовжити chain
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Якщо локальний exploit або спроба persistence постійно завершується помилкою `EACCES` чи дивними помилками "permission denied", незважаючи на дозволи DAC, які виглядають як root, зазвичай варто перевірити SELinux, перш ніж відкидати цей вектор.

## Користувачі SELinux

Окрім звичайних користувачів Linux, існують користувачі SELinux. Кожен користувач Linux зіставляється з користувачем SELinux у межах policy, що дає системі змогу призначати різним обліковим записам різні дозволені ролі та домени.<sup>[[3]](#references)</sup>

Швидкі перевірки:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
У багатьох поширених системах користувачі зіставляються з `unconfined_u`, що зменшує практичний вплив обмеження користувачів. Однак у посилено захищених середовищах обмежені користувачі можуть зробити `sudo`, `su`, `newrole` і `runcon` набагато цікавішими, оскільки **шлях ескалації може залежати від переходу до кращої ролі/типу SELinux, а не лише від отримання UID 0**. Також пам'ятайте, що деякі обмежені користувачі взагалі не можуть викликати `sudo`/`su`, якщо політика явно не дозволяє відповідний перехід setuid, тому хост із `staff_u` + `sysadm_r` може перетворити, на перший погляд, незначне правило `sudo ROLE=` / `TYPE=` на справжню межу привілеїв.<sup>[[3]](#references)</sup>

## SELinux у контейнерах

Середовища виконання контейнерів зазвичай запускають робочі навантаження в обмеженому домені, такому як `container_t`, і позначають вміст контейнера як `container_file_t`. Якщо процес контейнера вийде за межі контейнера, але продовжить працювати з міткою контейнера, запис на хост усе одно може бути неможливим, оскільки межа мітки залишилася чинною.

Короткий приклад:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Частина `c647,c780` — це не декоративний елемент. У багатьох розгортаннях контейнерів runtime динамічно призначає категорії MCS, щоб два процеси, які працюють як `container_t`, усе одно були ізольовані один від одного. Якщо після escape ви опинитеся в namespace хоста, але збережете початковий набір категорій, невідповідність категорій усе ще може пояснювати, чому деякі шляхи хоста залишаються недоступними для читання або запису.

Сучасні операції з контейнерами, на які варто звернути увагу:

- `--security-opt label=disable` може фактично перемістити workload до необмеженого типу, пов’язаного з контейнерами, наприклад `spc_t`
- bind mounts із `:z` / `:Z` запускають повторне маркування шляху хоста для спільного або приватного використання контейнером
- широке повторне маркування вмісту хоста саме по собі може стати проблемою безпеки

На цій сторінці матеріал про контейнери залишається стислим, щоб уникнути дублювання. Щоб ознайомитися зі специфічними для контейнерів сценаріями зловживання та прикладами runtime, перегляньте:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Посилання

- [1] [Документація Red Hat: Використання SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Інструменти аналізу політик для SELinux](https://github.com/SELinuxProject/setools)
- [3] [Керування обмеженими та необмеженими користувачами — документація RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
