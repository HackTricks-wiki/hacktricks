# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **Mandatory Access Control (MAC) на основі міток**. На практиці це означає, що навіть якщо дозволи DAC, групи або Linux capabilities здаються достатніми для виконання дії, kernel все одно може заборонити її, оскільки **source context** не має дозволу на доступ до **target context** із запитаним класом/дозволом.

Зазвичай context має такий вигляд:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З погляду `privesc`, поле `type` (домен для процесів, тип для об'єктів) зазвичай є найважливішим:

- Процес працює в **домені**, наприклад `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли й сокети мають **тип**, наприклад `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Політика визначає, чи може один домен читати, записувати, виконувати або переходити до іншого

## Швидке перерахування

Якщо SELinux увімкнено, перевірте його на ранньому етапі, оскільки це може пояснити, чому поширені шляхи `privesc` у Linux не працюють або чому привілейована обгортка навколо "нешкідливого" інструмента SELinux насправді є критично важливою:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Корисні додаткові перевірки:
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
Цікаві знахідки:

- Режими `Disabled` або `Permissive` позбавляють SELinux більшої частини його цінності як межі безпеки.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t` або явно неправильні мітки на користувацьких шляхах часто вказують на помилкове маркування чи неповне розгортання.
- Локальні перевизначення у `file_contexts.local` мають пріоритет над типовими параметрами policy, тому їх слід ретельно перевіряти.

## Аналіз policy

SELinux значно легше атакувати або обходити, коли можна відповісти на два запитання:

1. **До чого може отримати доступ мій поточний домен?**
2. **У які домени я можу перейти?**

Найкориснішими інструментами для цього є `sepolicy` та **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Це особливо корисно, коли хост використовує **confined users**, а не зіставляє всіх із `unconfined_u`. У такому разі шукайте:

- зіставлення користувачів через `semanage login -l`
- дозволені ролі через `semanage user -l`
- доступні адміністративні домени, такі як `sysadm_t`, `secadm_t`, `webadm_t`
- записи `sudoers`, що використовують `ROLE=` або `TYPE=`

Якщо `sudo -l` містить записи на кшталт цього, SELinux є частиною межі привілеїв:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступна `newrole`:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` і `newrole` не є автоматично експлуатованими, але якщо привілейований wrapper або правило `sudoers` дозволяє вибрати кращу роль/тип, вони стають цінними примітивами ескалації.

## Файли, переприсвоєння міток і важливі неправильні конфігурації

Найважливіша операційна відмінність між поширеними інструментами SELinux:

- `chcon`: тимчасова зміна мітки для певного шляху
- `semanage fcontext`: постійне правило відповідності шляху та мітки
- `restorecon` / `setfiles`: повторне застосування мітки згідно з політикою/типовою міткою

Це має велике значення під час privesc, оскільки **переприсвоєння міток — це не просто косметична зміна**. Воно може перетворити файл із такого, що "заблокований політикою", на такий, що "доступний для читання/виконання привілейованою confined-службою".

Перевірте локальні правила переприсвоєння міток і відхилення міток від очікуваних:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Одна тонка, але корисна деталь: звичайний `restorecon` **не завжди повністю скидає підозрілу мітку**. Якщо цільовий тип міститься в `customizable_types`, може знадобитися `-F`, щоб примусово виконати повне скидання. З offensive perspective це пояснює, чому незвичайний `chcon` іноді може зберегтися після поверхневої процедури очищення на кшталт «ми вже виконали restorecon».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Команди високої цінності для пошуку в `sudo -l`, root-обгортках, скриптах автоматизації або файлових capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Якщо з’являється будь-яка з можливостей MAC, додатково перевірте [сторінку Linux capabilities](linux-capabilities.md); `cap_mac_admin` і `cap_mac_override` є незвичними, але безпосередньо релевантними, коли SELinux є частиною межі безпеки.

Особливо цікаві:

- `semanage fcontext`: постійно змінює мітку, яку має отримувати шлях
- `restorecon` / `setfiles`: повторно застосовує ці зміни у великому масштабі
- `semodule -i`: завантажує користувацький policy module
- `semanage permissive -a <domain_t>`: робить один домен permissive, не перемикаючи весь хост
- `setsebool -P`: назавжди змінює policy booleans
- `load_policy`: перезавантажує активну policy

Часто це **допоміжні примітиви**, а не самостійні root exploits. Їхня цінність полягає в тому, що вони дають змогу:

- зробити цільовий домен permissive
- розширити доступ між вашим доменом і захищеним типом
- повторно призначити мітки файлам, контрольованим attacker, щоб privileged service міг їх читати або виконувати
- послабити обмеження для confined service настільки, щоб наявний local bug став exploitable

Приклади перевірок:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити модуль політики від імені root, ви зазвичай контролюєте межу SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Саме тому `audit2allow`, `semodule` і `semanage permissive` слід вважати чутливими поверхнями адміністрування під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюжок на робочий, не змінюючи класичні UNIX-права.

## Приховані відмови та вилучення модуля

Дуже поширена offensive-проблема — ланцюжок завершується звичайною помилкою `EACCES`, хоча очікувана відмова AVC не з’являється. Правила `dontaudit` можуть приховувати саме потрібний дозвіл. Якщо ви можете запускати `semodule` через `sudo` або іншу привілейовану обгортку, тимчасове вимкнення `dontaudit` може перетворити тихий збій на точну підказку щодо політики:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Це також корисно для перевірки того, що локальні адміністратори вже змінили. Невеликий custom module або permissive rule для одного домену часто є причиною того, що цільовий сервіс працює значно менш обмежено, ніж можна було б припустити з базової policy.

## Підказки для аудиту

AVC denials часто є offensive signal, а не просто defensive noise. Вони повідомляють:

- до якого target object/type ви звернулися
- яку permission було відхилено
- який domain ви наразі контролюєте
- чи зробила б невелика зміна policy цей ланцюжок робочим
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Якщо локальний exploit або спроба persistence постійно завершується помилкою `EACCES` чи дивними помилками «permission denied», незважаючи на DAC-права, що виглядають як root-права, зазвичай варто перевірити SELinux, перш ніж відкидати цей вектор.

## Користувачі SELinux

Окрім звичайних користувачів Linux, існують користувачі SELinux. Кожен користувач Linux зіставляється з користувачем SELinux як частина policy, що дає системі змогу призначати різні дозволені ролі та домени для різних облікових записів.

Швидкі перевірки:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
У багатьох поширених системах користувачі зіставляються з `unconfined_u`, що зменшує практичний вплив обмеження користувачів. Однак у hardened-розгортаннях confined-користувачі можуть зробити `sudo`, `su`, `newrole` і `runcon` набагато цікавішими, оскільки **шлях ескалації може залежати від переходу до кращої SELinux-ролі/типу, а не лише від отримання UID 0**. Також пам’ятайте, що деякі confined-користувачі взагалі не можуть викликати `sudo`/`su`, якщо policy явно не дозволяє відповідний setuid-перехід. Тому хост, який використовує `staff_u` + `sysadm_r`, може перетворити, на перший погляд, незначне правило `sudo ROLE=` / `TYPE=` на справжню межу привілеїв.

## SELinux у контейнерах

Container runtimes зазвичай запускають workloads у confined-домені, такому як `container_t`, і позначають вміст контейнера як `container_file_t`. Якщо container process виконає escape, але продовжить працювати з container label, запис на host усе одно може завершитися помилкою, оскільки label boundary залишилася незмінною.

Короткий приклад:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Частина `c647,c780` — це не декорація. У багатьох розгортаннях контейнерів runtime динамічно призначає категорії MCS, щоб два процеси, які працюють як `container_t`, усе одно були ізольовані один від одного. Якщо після escape ви опинилися в namespace хоста, але зберегли початковий набір категорій, невідповідність категорій усе ще може пояснювати, чому деякі шляхи хоста залишаються недоступними для читання або запису.

Сучасні аспекти роботи з контейнерами, на які варто звернути увагу:

- `--security-opt label=disable` може фактично перемістити workload до необмеженого типу, пов’язаного з контейнерами, наприклад `spc_t`
- bind mounts із `:z` / `:Z` запускають перемаркування шляху хоста для спільного/приватного використання контейнером
- широке перемаркування вмісту хоста саме по собі може стати проблемою безпеки

На цій сторінці матеріал про контейнери подано стисло, щоб уникнути дублювання. Приклади специфічних для контейнерів випадків зловживання та runtime дивіться тут:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Посилання

- [Документація Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Інструменти аналізу політик для SELinux](https://github.com/SELinuxProject/setools)
- [Керування обмеженими та необмеженими користувачами — документація RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
