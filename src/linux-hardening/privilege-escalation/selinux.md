# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **Mandatory Access Control (MAC)** на основі міток. На практиці це означає, що навіть якщо дозволів DAC, груп або Linux capabilities достатньо для певної дії, ядро все одно може її заборонити, оскільки **source context** не має дозволу на доступ до **target context** із запитаним class/permission.

Зазвичай context виглядає так:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
З точки зору privesc, `type` (domain для процесів, type для об’єктів) зазвичай є найважливішим полем:

- Процес виконується в **domain** такому як `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли та сокети мають **type** такий як `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy вирішує, чи може один domain читати/писати/виконувати/переходити до іншого

## Fast Enumeration

Якщо SELinux увімкнено, enumerate його якомога раніше, бо це може пояснити, чому типові Linux privesc paths не працюють, або чому привілейований wrapper навколо "harmless" SELinux tool насправді критичний:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Корисні наступні перевірки:
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
Цікаві спостереження:

- `Disabled` або `Permissive` режим знімає більшість цінності SELinux як межі.
- `unconfined_t` зазвичай означає, що SELinux присутній, але не обмежує цей процес суттєво.
- `default_t`, `file_t` або явно неправильні labels на custom paths часто вказують на неправильне маркування або неповне розгортання.
- Локальні override у `file_contexts.local` мають пріоритет над policy defaults, тому перевіряйте їх уважно.

## Policy Analysis

SELinux набагато легше атакувати або bypass, коли ви можете відповісти на два запитання:

1. **Що може доступати мій поточний domain?**
2. **У який domain я можу перейти?**

Найкорисніші tools для цього — `sepolicy` і **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Особливо корисно, коли хост використовує **confined users** замість того, щоб мапити всіх у `unconfined_u`. У такому разі шукай:

- user mappings через `semanage login -l`
- allowed roles через `semanage user -l`
- reachable admin domains, такі як `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` entries, що використовують `ROLE=` або `TYPE=`

Якщо `sudo -l` містить такі записи, SELinux є частиною межі privilege:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Також перевірте, чи доступний `newrole`:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` та `newrole` не є автоматично exploitable, але якщо привілейований wrapper або правило `sudoers` дозволяє вам вибрати кращий role/type, вони стають цінними primitives для escalation.

## Files, Relabeling, and High-Value Misconfigurations

Найважливіша operational difference між поширеними SELinux tools така:

- `chcon`: тимчасова зміна label для конкретного path
- `semanage fcontext`: persistent rule відповідності path-to-label
- `restorecon` / `setfiles`: повторно застосувати policy/default label

Це дуже важливо під час privesc, тому що **relabeling — це не просто косметична зміна**. Воно може перетворити файл із "blocked by policy" на "readable/executable by a privileged confined service".

Перевірте local relabel rules і relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Одна тонка, але корисна деталь: простий `restorecon` **не завжди повністю скасовує підозрілу мітку**. Якщо цільовий type входить до `customizable_types`, може знадобитися `-F`, щоб примусово виконати повне скидання. З offensive perspective це пояснює, чому незвичайний `chcon` інколи може пережити поверхове очищення на кшталт "we already ran restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Команди з високою цінністю для пошуку в `sudo -l`, root wrappers, automation scripts або file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Якщо з’являється будь-яка MAC capability, також звіртеся зі сторінкою [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` і `cap_mac_override` незвичні, але безпосередньо релевантні, коли SELinux є частиною межі.

Особливо цікаво:

- `semanage fcontext`: постійно змінює, який label має отримати path
- `restorecon` / `setfiles`: повторно застосовує ці зміни в масштабі
- `semodule -i`: завантажує custom policy module
- `semanage permissive -a <domain_t>`: робить один domain permissive, не перемикаючи весь host
- `setsebool -P`: постійно змінює policy booleans
- `load_policy`: перезавантажує активну policy

Це часто **helper primitives**, а не standalone root exploits. Їхня цінність у тому, що вони дають змогу вам:

- зробити цільовий domain permissive
- розширити доступ між вашим domain і protected type
- перелабелити файли під контролем attacker так, щоб privileged service міг їх прочитати або виконати
- достатньо послабити confined service, щоб існуюча local bug стала exploitable

Приклади перевірок:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Якщо ви можете завантажити policy module як root, зазвичай ви контролюєте межу SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Саме тому `audit2allow`, `semodule` і `semanage permissive` слід розглядати як чутливі admin surfaces під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюг на робочий без зміни класичних UNIX permissions.

## Hidden Denials and Module Extraction

Дуже поширена offensive проблема — це ланцюг, який завершується невибагливим `EACCES`, тоді як очікуваний AVC denial так і не з’являється. Правила `dontaudit` можуть приховувати саме той permission, який вам потрібен. Якщо ви можете запустити `semodule` через `sudo` або інший privileged wrapper, тимчасове вимкнення `dontaudit` може перетворити тиху помилку на точну policy clue:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Це також корисно для перевірки того, що local admins уже змінили. Невеликий custom module або one-domain permissive rule часто є причиною того, що цільовий service поводиться значно більш ліберально, ніж можна було б очікувати за base policy.

## Audit Clues

AVC denials часто є offensive signal, а не просто defensive noise. Вони кажуть вам:

- which target object/type you hit
- which permission was denied
- which domain you currently control
- whether a small policy change would make the chain work
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux usually is worth checking before discarding the vector.

## SELinux Users

Існують SELinux users додатково до звичайних Linux users. Кожен Linux user зіставляється з SELinux user як частина policy, що дозволяє системі накладати різні allowed roles and domains на різні облікові записи.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
На багатьох поширених системах користувачі зіставляються з `unconfined_u`, що зменшує практичний вплив user confinement. Однак на hardened deployments confined users можуть зробити `sudo`, `su`, `newrole` і `runcon` набагато цікавішими, тому що **шлях escalation може залежати від переходу в кращу SELinux role/type, а не лише від отримання UID 0**. Також пам’ятайте, що деякі confined users взагалі не можуть викликати `sudo`/`su`, якщо policy явно не дозволяє базовий setuid transition, тож host, який використовує `staff_u` + `sysadm_r`, може перетворити здавалося б незначне `sudo ROLE=` / `TYPE=` правило на реальну межу privileges.

## SELinux in Containers

Container runtimes зазвичай запускають workloads у confined domain, наприклад `container_t`, і позначають container content як `container_file_t`. Якщо container process escapes, але все ще працює з container label, host writes можуть і далі завершуватися помилкою, бо межа label залишилася неушкодженою.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Частина `c647,c780` — це не декорація. У багатьох контейнерних розгортаннях runtime динамічно призначають MCS categories, щоб два процеси, що працюють як `container_t`, усе одно були ізольовані один від одного. Якщо escape переносить вас у host namespace, але зберігає початковий набір category, невідповідність categories все ще може пояснити, чому деякі host paths залишаються недоступними для читання або запису.

Сучасні контейнерні операції, на які варто звернути увагу:

- `--security-opt label=disable` може фактично перемістити workload до unconfined контейнерного типу, такого як `spc_t`
- bind mounts з `:z` / `:Z` запускають relabeling host path для спільного/приватного використання контейнером
- широке relabeling вмісту host може саме по собі стати security issue

Ця сторінка тримає контент про контейнер коротким, щоб уникнути дублювання. Для container-specific abuse cases і прикладів runtime дивіться:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
