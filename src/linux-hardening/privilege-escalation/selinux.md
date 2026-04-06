# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **обов'язкового контролю доступу (MAC) на основі міток**. На практиці це означає, що навіть якщо права DAC, групи або Linux capabilities виглядають достатніми для виконання дії, ядро все одно може її заборонити, оскільки **source context** не має дозволу отримувати доступ до **target context** з запитуваним class/permission.

Контекст зазвичай виглядає так:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З точки зору privesc, поле `type` (domain for processes, type for objects) зазвичай є найважливішим полем:

- Процес працює в **domain** таких як `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли та сокети мають **type** такі як `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Політика визначає, чи може один domain read/write/execute/transition щодо іншого

## Швидка перевірка

Якщо SELinux увімкнено, перевіряйте його на початку, бо це може пояснити, чому звичайні Linux privesc шляхи не працюють або чому привілейований wrapper навколо "harmless" SELinux tool насправді критичний:
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
Цікаві знайдення:

- `Disabled` або `Permissive` режим суттєво позбавляє SELinux значущості як межі.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t` або очевидно неправильні мітки на користувацьких шляхах часто вказують на неправильне маркування або неповне розгортання.
- Локальні переозначення в `file_contexts.local` мають пріоритет над дефолтами політики, тож переглядайте їх уважно.

## Аналіз політики

SELinux набагато легше атакувати або обійти, якщо ви можете відповісти на два питання:

1. **До чого має доступ мій поточний домен?**
2. **У які домени я можу перейти?**

Найкорисніші інструменти для цього — `sepolicy` та **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Це особливо корисно, коли хост використовує **confined users** замість того, щоб призначати всім `unconfined_u`. У цьому випадку шукайте:

- відповідності користувачів через `semanage login -l`
- дозволені ролі через `semanage user -l`
- доступні адміністративні домени, наприклад `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` записи, які використовують `ROLE=` або `TYPE=`

Якщо `sudo -l` містить такі записи, то SELinux є частиною межі привілеїв:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступний `newrole`:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` і `newrole` не є автоматично експлуатованими, але якщо привілейований wrapper або правило `sudoers` дозволяє вам вибрати кращу роль/тип, вони стають високовартісними примітивами ескалації.

## Файли, перемаркування та критично важливі неправильні конфігурації

Найважливіша практична різниця між поширеними інструментами SELinux полягає в:

- `chcon`: тимчасова зміна мітки на конкретному шляху
- `semanage fcontext`: постійне правило зіставлення шляху з міткою
- `restorecon` / `setfiles`: заново застосовують політику/мітку за замовчуванням

Це має велике значення під час privesc, оскільки **перемаркування — це не просто косметична зміна**. Воно може перетворити файл зі стану «заблоковано політикою» на «доступний для читання та виконання привілейованою ізольованою службою».

Перевірте локальні правила перемаркування та дрейф міток:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Команди високої цінності для пошуку в `sudo -l`, root wrappers, скриптах автоматизації або файлових capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Особливо цікаве:

- `semanage fcontext`: постійно змінює, яку мітку має отримувати шлях
- `restorecon` / `setfiles`: повторно застосовують ці зміни в масштабі
- `semodule -i`: завантажує користувацький модуль політики
- `semanage permissive -a <domain_t>`: робить один домен пермісивним без переключення всього хоста
- `setsebool -P`: постійно змінює булі політики
- `load_policy`: перезавантажує активну політику

Це часто **допоміжні примітиви**, а не самостійні експлойти для root. Їхня цінність у тому, що вони дозволяють:

- зробити цільовий домен пермісивним
- розширити доступ між вашим доменом і захищеним типом
- перепризначити мітки файлам, контрольованим атакуючим, щоб привілейований сервіс міг їх читати або виконувати
- ослабити ізольований сервіс настільки, щоб існуюча локальна помилка стала експлуатованою

Приклади перевірок:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити модуль політики від імені root, ви зазвичай контролюєте межі SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Тому `audit2allow`, `semodule`, і `semanage permissive` слід розглядати як чутливі адміністративні поверхні під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюг на робочий, не змінюючи класичних UNIX-прав.

## Підказки аудиту

Відмови AVC часто служать сигналом для наступальних дій, а не лише захисним шумом. Вони підказують:

- який об'єкт/тип цілі ви вразили
- який дозвіл було відхилено
- який домен ви наразі контролюєте
- чи невелика зміна політики дозволить ланцюгу запрацювати
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Якщо local exploit або спроба persistence постійно завершується з `EACCES` або дивними "permission denied" помилками, незважаючи на root-looking DAC permissions, зазвичай варто перевірити SELinux перед відкиданням вектора.

## Користувачі SELinux

Існують користувачі SELinux, окрім звичайних користувачів Linux. Кожен користувач Linux відображається на користувача SELinux як частина політики, що дозволяє системі накладати різні дозволені ролі та домени на різні облікові записи.

Швидкі перевірки:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
На багатьох поширених системах користувачам призначається `unconfined_u`, що зменшує практичний вплив ізоляції користувача. Проте в жорстко захищених розгортаннях обмежені користувачі можуть зробити `sudo`, `su`, `newrole` і `runcon` набагато цікавішими, оскільки **шлях ескалації може залежати від переходу в кращу роль/тип SELinux, а не лише від отримання UID 0**.

## SELinux у контейнерах

Середовища виконання контейнерів зазвичай запускають робочі процеси в обмеженому домені, наприклад `container_t`, і маркують вміст контейнера як `container_file_t`. Якщо процес контейнера вийде за межі контейнера, але все ще працюватиме з міткою контейнера, операції запису на хості все одно можуть не виконуватись, оскільки межа мітки залишилася непошкодженою.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Сучасні операції з контейнерами, на які варто звернути увагу:

- `--security-opt label=disable` фактично може перемістити робоче навантаження в неконтрольований пов'язаний з контейнером тип, такий як `spc_t`
- bind mounts з `:z` / `:Z` викликають релейблінг шляху на хості для спільного/приватного використання контейнером
- широке релейблінг вмісту хоста може стати проблемою безпеки само по собі

Ця сторінка зберігає інформацію про контейнери короткою, щоб уникнути дублювання. Для специфічних для контейнерів випадків зловживання та прикладів під час виконання, перегляньте:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Джерела

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
