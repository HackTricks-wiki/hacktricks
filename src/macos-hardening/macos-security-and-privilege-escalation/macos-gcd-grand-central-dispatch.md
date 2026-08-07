# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

**Grand Central Dispatch (GCD),** também conhecido como **libdispatch** (`libdispatch.dyld`), está disponível tanto no macOS quanto no iOS. É uma tecnologia desenvolvida pela Apple para otimizar o suporte das aplicações à execução concorrente (multithreaded) em hardware multicore.<sup>[[4]](#references)</sup>

**GCD** fornece e gerencia **filas FIFO** às quais sua aplicação pode **enviar tarefas** na forma de **block objects**. Os blocks enviados às dispatch queues são **executados em um pool de threads** totalmente gerenciado pelo sistema. O GCD cria automaticamente threads para executar as tarefas nas dispatch queues e agenda essas tarefas para serem executadas nos cores disponíveis.<sup>[[1]](#references)</sup>

> [!TIP]
> Em resumo, para executar código em **paralelo**, os processos podem enviar **blocos de código ao GCD**, que cuidará da execução. Portanto, os processos não criam novas threads; **o GCD executa o código fornecido com seu próprio pool de threads** (que pode aumentar ou diminuir conforme necessário).

Isso é muito útil para gerenciar com sucesso a execução paralela, reduzindo bastante o número de threads criadas pelos processos e otimizando a execução paralela. Isso é ideal para tarefas que exigem **grande paralelismo** (brute-forcing?) ou para tarefas que não devem bloquear a thread principal: por exemplo, a thread principal no iOS gerencia as interações da UI, portanto qualquer outra funcionalidade que possa fazer o aplicativo travar (pesquisar, acessar a web, ler um arquivo...) é gerenciada dessa forma.

### Blocks

Um block é uma **seção de código autocontida** (como uma função com argumentos que retorna um valor) e também pode especificar variáveis vinculadas.\
No entanto, no nível do compilador, blocks não existem; eles são `os_object`s. Cada um desses objetos é formado por duas estruturas:

- **block literal**:
- Ele começa pelo campo **`isa`**, que aponta para a classe do block:
- `NSConcreteGlobalBlock` (blocks de `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks no heap)
- `NSConcreateStackBlock` (blocks na stack)
- Ele possui **`flags`** (indicando os campos presentes no block descriptor) e alguns bytes reservados
- O ponteiro da função a ser chamada
- Um ponteiro para o block descriptor
- Variáveis importadas pelo block (se houver)
- **block descriptor**: seu tamanho depende dos dados presentes (conforme indicado pelas flags anteriores)
- Ele possui alguns bytes reservados
- O tamanho dele
- Normalmente terá um ponteiro para uma assinatura no estilo Objective-C para saber quanto espaço é necessário para os parâmetros (flag `BLOCK_HAS_SIGNATURE`)
- Se houver variáveis referenciadas, esse block também terá ponteiros para um copy helper (que copia o valor no início) e um dispose helper (que o libera).

### Queues

Uma dispatch queue é um objeto nomeado que fornece ordenação FIFO de blocks para execução.<sup>[[3]](#references)</sup>

Os blocks são definidos nas queues para serem executados, e elas oferecem 2 modos: `DISPATCH_QUEUE_SERIAL` e `DISPATCH_QUEUE_CONCURRENT`. Naturalmente, a queue **serial** **não terá** problemas de **race condition**, pois um block não será executado até que o anterior tenha terminado. Porém, **o outro tipo de queue pode apresentar esse problema**.

Queues padrão:

- `.main-thread`: De `dispatch_get_main_queue()`
- `.libdispatch-manager`: Gerenciador de queues do GCD
- `.root.libdispatch-manager`: Gerenciador de queues do GCD
- `.root.maintenance-qos`: Tarefas de menor prioridade
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Disponível como `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Disponível como `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Disponível como `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Disponível como `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Maior prioridade
- `.root.background-qos.overcommit`

Observe que será o sistema que decidirá **quais threads gerenciam quais queues em cada momento** (várias threads podem trabalhar na mesma queue, ou a mesma thread pode trabalhar em queues diferentes em algum momento).

#### Attributtes

Ao criar uma queue com **`dispatch_queue_create`**, o terceiro argumento é um `dispatch_queue_attr_t`, que normalmente é `DISPATCH_QUEUE_SERIAL` (que na verdade é NULL) ou `DISPATCH_QUEUE_CONCURRENT`, que é um ponteiro para uma estrutura `dispatch_queue_attr_t` que permite controlar alguns parâmetros da queue.

### Dispatch objects

Existem vários objetos que o libdispatch utiliza, e queues e blocks são apenas 2 deles. É possível criar esses objetos com `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Blocos de dados
- `group`: Grupo de blocks
- `io`: Requisições de I/O assíncronas
- `mach`: Portas Mach
- `mach_msg`: Mensagens Mach
- `pthread_root_queue`: Uma queue com um pool de threads pthread e sem workqueues
- `queue`
- `semaphore`
- `source`: Fonte de eventos

## Objective-C

No Objetive-C, existem diferentes funções para enviar um block para ser executado em paralelo:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Envia um block para execução assíncrona em uma dispatch queue e retorna imediatamente.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Envia um block object para execução e retorna após o término da execução desse block.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Executa um block object apenas uma vez durante o tempo de vida de uma aplicação.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Envia um work item para execução e retorna somente após o término da execução. Diferentemente de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), essa função respeita todos os atributos da queue ao executar o block.

Essas funções esperam estes parâmetros: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Esta é a **struct de um Block**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
E este é um exemplo de uso de **paralelismo** com **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** é uma biblioteca que fornece **bindings Swift** para o framework Grand Central Dispatch (GCD), originalmente escrito em C.\
A biblioteca **`libswiftDispatch`** encapsula as APIs GCD em C em uma interface mais amigável ao Swift, tornando mais fácil e intuitivo para desenvolvedores Swift trabalhar com GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Exemplo de código**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

O script do Frida a seguir pode ser usado para **fazer hook em várias funções `dispatch`** e extrair o nome da queue, o backtrace e o block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Atualmente, o Ghidra não entende nem a estrutura **`dispatch_block_t`** do Objective-C, nem a estrutura **`swift_dispatch_block`**.

Então, se quiser que ele as entenda, basta **declará-las**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Depois, encontre um local no código onde elas são **usadas**:

> [!TIP]
> Observe todas as referências feitas a "block" para entender como você poderia descobrir que a struct está sendo usada.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Clique com o botão direito na variável -> Retype Variable e, neste caso, selecione **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

O Ghidra reescreverá tudo automaticamente:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referências

- [1] [libdispatch — `src/queue.c` (implementação de queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API pública de queue)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
