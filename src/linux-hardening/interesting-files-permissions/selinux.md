# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux — це система **обов’язкового контролю доступу (MAC)** на основі міток. На практиці це означає, що навіть якщо дозволів DAC, груп або можливостей Linux, здається, достатньо для виконання дії, ядро все одно може її заборонити, оскільки **вихідному контексту** не дозволено доступ до **цільового контексту** з потрібним класом/дозволом.<sup>[[1]](#references)</sup>

Контекст зазвичай має такий вигляд:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

З погляду privesc, `type` (домен для процесів, тип для об’єктів) зазвичай є найважливішим полем:<sup>[[1]](#references)</sup>

- Процес працює в **домені**, наприклад `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Файли й сокети мають **тип**, наприклад `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Політика визначає, чи може один домен читати, записувати, виконувати або переходити до іншого

## Швидке перерахування

Якщо SELinux увімкнено, перевірте його на ранньому етапі: це може пояснити, чому поширені шляхи підвищення привілеїв у Linux не спрацьовують або чому привілейована обгортка навколо «нешкідливого» інструмента SELinux насправді має критичне значення:<sup>[[1]](#references)</sup>

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

Цікаві спостереження:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Режим `Disabled` або `Permissive` позбавляє SELinux більшої частини його здатності слугувати межею безпеки.
- `unconfined_t` зазвичай означає, що SELinux присутній, але фактично не обмежує цей процес.
- `default_t`, `file_t` або явно неправильні мітки на користувацьких шляхах часто вказують на неправильне маркування чи неповне розгортання.
- Локальні перевизначення у `file_contexts.local` мають пріоритет над типовими налаштуваннями політики, тож уважно їх перевіряйте.

## Аналіз політики

SELinux набагато легше атакувати або обходити, якщо ви можете відповісти на два запитання:

1. **До чого може отримати доступ мій поточний домен?**
2. **До яких доменів я можу перейти?**

Найкорисніші інструменти для цього — `sepolicy` і **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

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

Це особливо корисно, якщо хост використовує **обмежених користувачів**, а не зіставляє всіх із `unconfined_u`. У такому разі шукайте:<sup>[[3]](#references)</sup>

- зіставлення користувачів через `semanage login -l`
- дозволені ролі через `semanage user -l`
- доступні адміністративні домени, як-от `sysadm_t`, `secadm_t`, `webadm_t`
- записи `sudoers` із `ROLE=` або `TYPE=`

Якщо `sudo -l` містить такі записи, SELinux є частиною межі привілеїв:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Також перевірте, чи доступний `newrole`:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` і `newrole` не є автоматично експлуатованими, але якщо привілейована обгортка або правило `sudoers` дозволяє вибрати кориснішу роль/тип, вони стають цінними примітивами для підвищення привілеїв.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Перевірка доступних для запису точок входу переходу

Граф переходів — це лише підказка щодо політики. Щоб перетворити його на шлях атаки, визначте тип виконуваного файла, який переводить у корисніший домен, а потім перевірте, чи можете ви змінити виконуваний файл із цією міткою або підмінити його через батьківський каталог.<sup>[[9]](#references)[[20]](#references)</sup> Для автоматичного переходу `execve` потрібні відповідне правило `type_transition`, дозвіл на виконання у вихідному домені, дозвіл `entrypoint` у цільовому домені та дозвіл на перехід між доменами.<sup>[[20]](#references)</sup> Цільовий домен може отримати доступ SELinux, але саме виконання не змінює UID Linux; окремо перевірте [SUID/SGID та ACL](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Зафіксуйте тип точки входу, щоб перевірити відповідні правила, а потім перевірте шлях і його батьківський каталог на наявність доступу для запису.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Пов’яжіть тип entrypoint із фактичним шляхом до виконуваного файла. Перевірте DAC, ACL, дозвіл SELinux на запис у файл або батьківський каталог, мітку файла та будь-який умовний boolean, перш ніж вважати ребро політики досяжним.<sup>[[20]](#references)[[22]](#references)</sup> Якщо шлях замінюють, а не редагують на місці, перевірте контекст нового inode: мітки файлової системи зберігаються як розширені атрибути, і після заміни тип entrypoint може не зберегтися.<sup>[[21]](#references)</sup> Програми, що враховують SELinux, можуть запитувати перехід за допомогою `setexeccon`, тож відсутність автоматичного правила `type_transition` не виключає всіх можливих переходів.<sup>[[20]](#references)</sup>

## Файли, перемаркування та високоризикові помилкові налаштування

Найважливіша практична відмінність між поширеними інструментами SELinux:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: тимчасова зміна мітки для певного шляху
- `semanage fcontext`: постійне правило відповідності шляху й мітки
- `restorecon` / `setfiles`: повторне застосування мітки з політики/за замовчуванням

Це дуже важливо під час privesc, оскільки **перемаркування — це не просто косметична зміна**. Воно може перетворити файл із «заблокованого політикою» на «доступний для читання/виконання привілейованою службою з обмеженнями».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Перевірте локальні правила перемаркування та відхилення міток від належних:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Одна тонка, але корисна деталь: звичайний `restorecon` **не завжди повністю скидає підозрілу мітку**. Якщо цільовий тип є в `customizable_types`, може знадобитися `-F`, щоб примусово виконати повне скидання. З погляду атакувальника це пояснює, чому незвичний `chcon` іноді може зберегтися після поверхового очищення з фразою «ми вже запускали restorecon».<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Команди, які варто шукати в `sudo -l`, root-обгортках, скриптах автоматизації або файлових capabilities:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Якщо з’явиться будь-яка з можливостей MAC, також звіртеся зі [сторінкою Linux capabilities](linux-capabilities.md); документація Linux capabilities описує `cap_mac_admin` і `cap_mac_override` як специфічні для Smack, тож не припускайте, що самі лише їхні назви дають змогу обійти SELinux.<sup>[[5]](#references)</sup>

Особливо цікаві:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: постійно змінює мітку, яку має отримувати шлях
- `restorecon` / `setfiles`: повторно застосовують ці зміни у великому масштабі
- `semodule -i`: завантажує користувацький модуль політики
- `semanage permissive -a <domain_t>`: переводить один домен у permissive-режим, не змінюючи режим усього хоста
- `setsebool -P`: постійно змінює логічні перемикачі політики
- `load_policy`: перезавантажує активну політику

Часто це **допоміжні примітиви**, а не самостійні експлойти для отримання root. Їхня цінність у тому, що вони дають змогу:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- перевести цільовий домен у permissive-режим
- розширити доступ між вашим доменом і захищеним типом
- змінити мітки файлів, контрольованих зловмисником, щоб привілейована служба могла їх читати або виконувати
- послабити обмеження для ізольованої служби настільки, щоб наявну локальну вразливість можна було експлуатувати

Приклади перевірок:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Якщо ви можете завантажити модуль політики від імені root, зазвичай ви контролюєте межу SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Саме тому `audit2allow`, `semodule` і `semanage permissive` слід вважати чутливими адміністративними інтерфейсами під час post-exploitation. Вони можуть непомітно перетворити заблокований ланцюжок на робочий, не змінюючи класичних дозволів UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Приховані відмови та вилучення модулів

Дуже поширена проблема в offensive-діяльності — ланцюжок завершується звичайною помилкою `EACCES`, але очікувана відмова AVC не з’являється. Правила `dontaudit` можуть приховувати саме той дозвіл, який вам потрібен. Якщо ви можете запускати `semodule` через `sudo` або іншу привілейовану обгортку, тимчасове вимкнення `dontaudit` може перетворити непомітний збій на точну підказку щодо політики:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Це також корисно для перевірки змін, уже внесених локальними адміністраторами. Невеликий власний модуль або permissive-правило для одного домену часто є причиною того, що цільовий сервіс поводиться значно менш суворо, ніж можна було б припустити з базової політики.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Підказки для аудиту

Відмови AVC часто є сигналом для атакувальника, а не просто захисним шумом. Вони повідомляють вам:<sup>[[1]](#references)[[15]](#references)</sup>

- до якого цільового об’єкта/типу ви звернулися
- у якому дозволі було відмовлено
- яким доменом ви зараз керуєте
- чи допомогла б невелика зміна політики виконати ланцюжок атаки

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Якщо локальний exploit або спроба закріплення постійно завершується помилкою `EACCES` чи дивними помилками «permission denied», попри дозволи DAC, які виглядають як root, перед тим як відмовлятися від цього вектора, зазвичай варто перевірити SELinux.<sup>[[1]](#references)</sup>

## Користувачі SELinux

Окрім звичайних користувачів Linux, є користувачі SELinux. У межах політики кожен користувач Linux зіставляється з користувачем SELinux, що дає змогу системі призначати різні дозволені ролі й домени різним обліковим записам.<sup>[[3]](#references)</sup>

Швидкі перевірки:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

У багатьох поширених системах користувачів зіставляють із `unconfined_u`, що зменшує практичний вплив обмеження користувачів. Однак у системах із посиленим захистом обмежені користувачі роблять `sudo`, `su`, `newrole` і `runcon` значно цікавішими, адже **шлях підвищення привілеїв може залежати від переходу до привілейованішої ролі/типу SELinux, а не лише від отримання UID 0**. Також пам’ятайте, що деякі обмежені користувачі взагалі не можуть запускати `sudo`/`su`, якщо політика явно не дозволяє відповідний перехід setuid. Тож на хості з `staff_u` + `sysadm_r` правило `sudo ROLE=` / `TYPE=`, яке здається незначним, може насправді визначати межу привілеїв.<sup>[[3]](#references)</sup>

## SELinux у контейнерах

Середовища виконання контейнерів зазвичай запускають робочі навантаження в обмеженому домені, наприклад `container_t`, і призначають вмісту контейнера мітку `container_file_t`. Якщо процес контейнера вирветься назовні, але й надалі працюватиме з міткою контейнера, запис на хост усе ще може бути неможливим, оскільки межа міток залишилася незмінною.<sup>[[1]](#references)[[17]](#references)</sup>

Короткий приклад:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Частина `c647,c780` — це не декорація. У багатьох розгортаннях контейнерів середовища виконання динамічно призначають категорії MCS, щоб два процеси з типом `container_t` усе одно були ізольовані один від одного. Якщо під час escape ви потрапите в простір імен хоста, але збережете початковий набір категорій, невідповідність категорій усе ще може пояснювати, чому деякі шляхи хоста залишаються недоступними для читання або запису.<sup>[[17]](#references)</sup>

Сучасні операції з контейнерами, на які варто звернути увагу:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` вимикає ізоляцію контейнера за SELinux-мітками
- bind mounts із `:z` / `:Z` запускають перемаркування шляху хоста для спільного/приватного використання контейнером
- широке перемаркування вмісту хоста саме по собі може стати проблемою безпеки

На цій сторінці розділ про контейнери стислий, щоб уникнути дублювання. Приклади зловживань і приклади для середовищ виконання, специфічні для контейнерів, дивіться тут:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Документація Red Hat: використання SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: інструменти аналізу політик для SELinux](https://github.com/SELinuxProject/setools)
- [3] [Керування обмеженими й необмеженими користувачами — документація RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
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
- [17] [Чому варто використовувати Multi-Category Security для контейнерів Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Документація Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Посібник SELinux: переходи доменів і об’єктів](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: використання SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Посібник SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
