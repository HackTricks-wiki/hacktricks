# Injeção de Thread no macOS via porta de tarefa

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Este post foi copiado de [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/) (que contém mais informações)

### Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. Sequestro de Thread

A primeira coisa que fazemos é chamar **`task_threads()`** na porta da tarefa para obter uma lista de threads na tarefa remota e, em seguida, escolher um deles para sequestrar. Ao contrário dos frameworks de injeção de código tradicionais, **não podemos criar uma nova thread remota** porque `thread_create_running()` será bloqueado pela nova mitigação.

Então, podemos chamar **`thread_suspend()`** para parar a execução da thread.

Neste ponto, o único controle útil que temos sobre a thread remota é **pará-la**, **iniciá-la**, **obter** seus **valores de registro** e **definir** seus **valores de registro**. Assim, podemos **iniciar uma chamada de função remota** definindo os **registradores** `x0` a `x7` na thread remota para os **argumentos**, **definindo** **`pc`** para a função que queremos executar e iniciando a thread. Neste ponto, precisamos detectar o retorno e garantir que a thread não falhe.

Existem algumas maneiras de fazer isso. Uma maneira seria **registrar um manipulador de exceção** para a thread remota usando `thread_set_exception_ports()` e definir o registro de endereço de retorno, `lr`, para um endereço inválido antes de chamar a função; dessa forma, após a execução da função, uma exceção seria gerada e uma mensagem seria enviada para nossa porta de exceção, momento em que podemos inspecionar o estado da thread para recuperar o valor de retorno. No entanto, para simplificar, copiei a estratégia usada na exploração triple\_fetch de Ian Beer, que foi **definir `lr` para o endereço de uma instrução que entraria em loop infinito** e, em seguida, verificar repetidamente os registradores da thread até que **`pc` apontasse para essa instrução**.

### 2. Portas Mach para comunicação

O próximo passo é **criar portas Mach por meio das quais podemos nos comunicar com a thread remota**. Essas portas Mach serão úteis posteriormente para ajudar a transferir direitos de envio e recebimento arbitrários entre as tarefas.

Para estabelecer comunicação bidirecional, precisaremos criar dois direitos de recebimento Mach: um na **tarefa local e outro na tarefa remota**. Em seguida, precisaremos **transferir um direito de envio** para cada porta **para a outra tarefa**. Isso dará a cada tarefa uma maneira de enviar uma mensagem que pode ser recebida pela outra.

Vamos primeiro nos concentrar em configurar a porta local, ou seja, a porta para a qual a tarefa local detém o direito de recebimento. Podemos criar a porta Mach como qualquer outra, chamando `mach_port_allocate()`. O truque é obter um direito de envio para essa porta na tarefa remota.

Um truque conveniente que podemos usar para copiar um direito de envio da tarefa atual para uma tarefa remota usando apenas um primitivo básico de execução é armazenar um **direito de envio para nossa porta local na porta especial `THREAD_KERNEL_PORT` da thread remota** usando `thread_set_special_port()`; em seguida, podemos fazer a thread remota chamar `mach_thread_self()` para recuperar o direito de envio.

Em seguida, configuraremos a porta remota, que é praticamente o inverso do que acabamos de fazer. Podemos fazer a **thread remota alocar uma porta Mach chamando `mach_reply_port()`**; não podemos usar `mach_port_allocate()` porque este último retorna o nome da porta alocada na memória e ainda não temos uma primitiva de leitura. Depois de termos uma porta, podemos criar um direito de envio chamando `mach_port_insert_right()` na thread remota. Em seguida, podemos armazenar a porta no kernel chamando `thread_set_special_port()`. Finalmente, de volta à tarefa local, podemos recuperar a porta chamando `thread_get_special_port()` na thread remota, **dando-nos um direito de envio para a porta Mach acabada de alocar na tarefa remota**.

Neste ponto, criamos as portas Mach que usaremos para comunicação bidirecional.
### 3. Leitura/escrita básica de memória <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

Agora usaremos o primitivo execute para criar primitivos básicos de leitura e escrita de memória. Esses primitivos não serão usados para muito (em breve atualizaremos para primitivos muito mais poderosos), mas são um passo fundamental para nos ajudar a expandir nosso controle sobre o processo remoto.

Para ler e escrever memória usando nosso primitivo execute, estaremos procurando por funções como estas:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Eles podem corresponder ao seguinte assembly:
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
Uma rápida análise de algumas bibliotecas comuns revelou alguns bons candidatos. Para ler a memória, podemos usar a função `property_getName()` da [biblioteca de tempo de execução Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html):
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
Acontece que `prop` é o primeiro campo de `objc_property_t`, então isso corresponde diretamente à hipotética `read_func` acima. Só precisamos realizar uma chamada de função remota com o primeiro argumento sendo o endereço que queremos ler, e o valor de retorno será os dados nesse endereço.

Encontrar uma função pré-fabricada para escrever na memória é um pouco mais difícil, mas ainda há ótimas opções sem efeitos colaterais indesejados. No libxpc, a função `_xpc_int64_set_value()` tem a seguinte desmontagem:
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
Assim, para realizar uma escrita de 64 bits no endereço `address`, podemos realizar a chamada remota:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Com esses primitivos em mãos, estamos prontos para criar memória compartilhada.

### 4. Memória compartilhada

Nosso próximo passo é criar memória compartilhada entre as tarefas locais e remotas. Isso nos permitirá transferir dados entre os processos com mais facilidade: com uma região de memória compartilhada, a leitura e gravação de memória arbitrária é tão simples quanto uma chamada remota para `memcpy()`. Além disso, ter uma região de memória compartilhada nos permitirá configurar facilmente uma pilha para que possamos chamar funções com mais de 8 argumentos.

Para facilitar as coisas, podemos reutilizar os recursos de memória compartilhada do libxpc. O libxpc fornece um tipo de objeto XPC, `OS_xpc_shmem`, que permite estabelecer regiões de memória compartilhada sobre XPC. Ao reverter o libxpc, determinamos que `OS_xpc_shmem` é baseado em entradas de memória Mach, que são portas Mach que representam uma região de memória virtual. E como já mostramos como enviar portas Mach para a tarefa remota, podemos usar isso para configurar facilmente nossa própria memória compartilhada.

Primeiro as coisas primeiro, precisamos alocar a memória que compartilharemos usando `mach_vm_allocate()`. Precisamos usar `mach_vm_allocate()` para que possamos usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região. `xpc_shmem_create()` cuidará de criar a entrada de memória Mach para nós e armazenará o direito de envio Mach para a entrada de memória no objeto `OS_xpc_shmem` opaco no deslocamento `0x18`.

Depois de obtermos a porta de entrada de memória, criaremos um objeto `OS_xpc_shmem` no processo remoto representando a mesma região de memória, permitindo-nos chamar `xpc_shmem_map()` para estabelecer o mapeamento de memória compartilhada. Primeiro, realizamos uma chamada remota para `malloc()` para alocar memória para o `OS_xpc_shmem` e usamos nosso primitivo de gravação básico para copiar o conteúdo do objeto `OS_xpc_shmem` local. Infelizmente, o objeto resultante não está totalmente correto: seu campo de entrada de memória Mach no deslocamento `0x18` contém o nome da tarefa local para a entrada de memória, não o nome da tarefa remota. Para corrigir isso, usamos o truque `thread_set_special_port()` para inserir um direito de envio para a entrada de memória Mach na tarefa remota e, em seguida, sobrescrevemos o campo `0x18` com o nome da entrada de memória remota. Neste ponto, o objeto `OS_xpc_shmem` remoto é válido e o mapeamento de memória pode ser estabelecido com uma chamada remota para `xpc_shmem_remote()`.

### 5. Controle total <a href="#step-5-full-control" id="step-5-full-control"></a>

Com memória compartilhada em um endereço conhecido e um primitivo de execução arbitrário, estamos basicamente prontos. Leituras e gravações de memória arbitrárias são implementadas chamando `memcpy()` para e da região compartilhada, respectivamente. Chamadas de função com mais de 8 argumentos são realizadas colocando argumentos adicionais além dos primeiros 8 na pilha de acordo com a convenção de chamada. A transferência de portas Mach arbitrárias entre as tarefas pode ser feita enviando mensagens Mach sobre as portas estabelecidas anteriormente. Podemos até transferir descritores de arquivos entre os processos usando fileports (um agradecimento especial a Ian Beer por demonstrar essa técnica em triple\_fetch!).

Em resumo, agora temos controle total e fácil sobre o processo vítima. Você pode ver a implementação completa e a API exposta na biblioteca [threadexec](https://github.com/bazad/threadexec).
