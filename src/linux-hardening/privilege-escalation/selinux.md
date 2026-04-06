# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **на основі міток обов'язкового контролю доступу (MAC)**. На практиці це означає, що навіть якщо DAC permissions, групи або Linux capabilities здаються достатніми для виконання дії, ядро все одно може відмовити, бо **контекст джерела** не має дозволу доступу до **цільового контексту** з запитуваним класом/дозволом.

Контекст зазвичай виглядає так:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З точки зору privesc, поле `type` (домен для процесів, тип для об'єктів) зазвичай є найважливішим:

- Процес працює в **домені**, наприклад `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли та сокети мають **тип**, наприклад `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Політика визначає, чи може один домен читати, записувати, виконувати або переходити в інший

## Швидка перевірка

Якщо SELinux увімкнено, перевіряйте його якомога раніше, бо це може пояснити, чому звичайні шляхи Linux privesc не працюють або чому привілейована wrapper навколо "harmless" SELinux інструмента насправді критична:
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
Цікаві знахідки:

- `Disabled` або `Permissive` режим позбавляє SELinux більшості цінності як межі.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t`, або очевидно неправильні мітки на користувацьких шляхах часто вказують на неправильне маркування або неповне розгортання.
- Локальні перевизначення в `file_contexts.local` мають пріоритет над значеннями політики за замовчуванням, тому ретельно їх переглядайте.

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
Це особливо корисно, коли хост використовує **обмежених користувачів**, замість того щоб відображати всіх на `unconfined_u`. У такому випадку зверніть увагу на:

- user mappings via `semanage login -l`
- allowed roles via `semanage user -l`
- reachable admin domains such as `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` entries using `ROLE=` or `TYPE=`

Якщо `sudo -l` містить такі записи, SELinux є частиною межі привілеїв:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступний `newrole`:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` та `newrole` не є автоматично експлуатованими, але якщо привілейований wrapper або правило `sudoers` дозволяє вибрати кращу роль/тип, вони стають високовартісними примітивами для ескалації.

## Файли, перетегування і конфігураційні помилки високої цінності

Найважливіша операційна різниця між звичайними інструментами SELinux полягає в наступному:

- `chcon`: тимчасова зміна мітки для конкретного шляху
- `semanage fcontext`: постійне правило призначення мітки для шляху
- `restorecon` / `setfiles`: повторно застосувати політику/мітку за замовчуванням

Це має велике значення під час privesc, тому що **перетегування — це не лише косметика**. Воно може перетворити файл з «заблокованого політикою» на «читаний/виконуваний привілейованим обмеженим сервісом».

Перевірте локальні правила перетегування та дрейф їх застосування:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Команди високої цінності для пошуку в `sudo -l`, root wrappers, automation scripts або file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Особливо цікаві:

- `semanage fcontext`: постійно змінює, яку мітку має отримувати шлях
- `restorecon` / `setfiles`: повторно застосовує ці зміни масово
- `semodule -i`: завантажує користувацький модуль політики
- `semanage permissive -a <domain_t>`: переводить один домен у режим permissive без переключення всього хоста
- `setsebool -P`: постійно змінює булеві параметри політики
- `load_policy`: перезавантажує активну політику

Це часто є **допоміжними примітивами**, а не самостійними експлоїтами для root. Їхня цінність у тому, що вони дозволяють вам:

- перевести цільовий домен у режим permissive
- розширити доступ між вашим доменом і захищеним типом
- переназначити мітки файлів, контрольованих атакуючим, щоб привілейований сервіс міг їх читати або виконувати
- ослабити ізольований сервіс настільки, що існуюча локальна помилка стане експлуатованою

Приклади перевірок:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити модуль політики як root, зазвичай ви контролюєте межу SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Ось чому `audit2allow`, `semodule`, і `semanage permissive` слід вважати чутливими адміністративними поверхнями під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюжок у працездатний, не змінюючи класичних UNIX-прав доступу.

## Підказки аудиту

AVC denials часто є сигналом для наступальних дій, а не просто захисним шумом. Вони повідомляють вам:

- який цільовий об'єкт/тип ви вразили
- який дозвіл було відхилено
- який domain ви наразі контролюєте
- чи невелика зміна політики зробить ланцюжок працездатним
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Якщо local exploit або persistence спроба продовжує завершуватись з `EACCES` або дивними помилками "permission denied", незважаючи на DAC-права, що виглядають як root, зазвичай варто перевірити SELinux перед тим, як відкидати вектор.

## Користувачі SELinux

Окрім звичайних користувачів Linux, існують користувачі SELinux. Кожен користувач Linux у межах політики відображається на користувача SELinux, що дозволяє системі накладати різні дозволені ролі та домени на різні облікові записи.

Швидкі перевірки:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
На багатьох звичайних системах користувачам присвоюється `unconfined_u`, що зменшує практичний вплив обмеження користувача. У жорстко захищених розгортаннях, однак, обмежені користувачі роблять `sudo`, `su`, `newrole` та `runcon` набагато цікавішими, оскільки **шлях ескалації може залежати від переходу в кращу роль/тип SELinux, а не лише від отримання UID 0**.

## SELinux in Containers

Container runtimes commonly launch workloads in a confined domain such as `container_t` and label container content as `container_file_t`. If a container process escapes but still runs with the container label, host writes may still fail because the label boundary stayed intact.

Короткий приклад:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Сучасні операції з контейнерами, на які варто звернути увагу:

- `--security-opt label=disable` може фактично перемістити робоче навантаження в неконфайнований контейнерний тип, такий як `spc_t`
- bind-монти з `:z` / `:Z` спричиняють перемаркування шляху на хості для спільного/приватного використання контейнером
- широке перемаркування вмісту хоста може саме по собі стати проблемою безпеки

Ця сторінка скорочує розділ про контейнери, щоб уникнути дублювання. Для специфічних для контейнерів випадків зловживань та прикладів виконання в рантаймі дивіться:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Посилання

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
