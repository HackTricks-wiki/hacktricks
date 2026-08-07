# Abuso de Processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas sobre Processos

Um processo é uma instância de um executável em execução; no entanto, os processos não executam código, e sim as threads. Portanto, **os processos são apenas contêineres para threads em execução**, fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criaria uma cópia exata do processo atual; então, o **processo filho** geralmente chamaria **`execve`** para carregar o novo executável e executá-lo. Depois, **`vfork`** foi introduzido para tornar esse processo mais rápido, sem nenhuma cópia de memória.\
Em seguida, **`posix_spawn`** foi introduzido, combinando **`vfork`** e **`execve`** em uma única chamada e aceitando flags:

- `POSIX_SPAWN_RESETIDS`: Redefine os ids efetivos para os ids reais
- `POSIX_SPAWN_SETPGROUP`: Define a afiliação ao grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Define o comportamento padrão dos sinais
- `POSIX_SPAWN_SETSIGMASK`: Define a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executa no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa o alocador Nano do libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` em segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fecha todas as descrições de arquivos durante exec(2) por padrão
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiza os bits superiores do slide do ASLR

Além disso, `posix_spawn` permite especificar um array de **`posix_spawnattr`** que controla alguns aspectos do processo criado, e **`posix_spawn_file_actions`** para modificar o estado dos descritores.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai tiver morrido, o novo pai será o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()` e, até que isso aconteça, o filho permanece em estado zumbi, no qual ainda é listado, mas não consome recursos.

### PIDs

PIDs, identificadores de processos, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonamente e **nunca sofrem wraparound** (para evitar abusos).

### Grupos de Processos, Sessões e Coalitions

**Processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, os comandos em um script de shell estarão no mesmo grupo de processos, portanto é possível **enviar sinais para eles em conjunto** usando kill, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados dentro da sessão, a menos que iniciem sua própria sessão.

Coalition é outra forma de agrupar processos no Darwin. Um processo que ingressa em uma Coalition pode acessar recursos de pool, compartilhar um ledger ou enfrentar o Jetsam. Coalitions têm diferentes funções: Leader, XPC service, Extension.

### Credenciais e Personae

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o id de usuário e de grupo se o binário tiver o bit **`setuid/setgid`**.\
Existem várias funções para **definir novos uids/gids**.

A syscall **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações de grupo **de uma só vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a struct:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Informações básicas sobre Threads

1. **POSIX Threads (pthreads):** o macOS oferece suporte a POSIX threads (`pthreads`), que fazem parte de uma API padrão de threading para C/C++. A implementação de pthreads no macOS está em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread`, disponível publicamente. Essa biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criação de Threads:** a função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, que é uma system call de nível inferior específica do kernel XNU (o kernel no qual o macOS se baseia). Essa system call recebe várias flags derivadas de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de escalonamento e o tamanho da stack.
- **Tamanho padrão da stack:** o tamanho padrão da stack para novas threads é de 512 KB, o que é suficiente para operações típicas, mas pode ser ajustado por meio dos atributos da thread caso seja necessário mais ou menos espaço.
3. **Inicialização de Threads:** a função `__pthread_init()` é essencial durante a configuração da thread, utilizando o argumento `env[]` para analisar variáveis de ambiente que podem incluir detalhes sobre a localização e o tamanho da stack.

#### Encerramento de Threads no macOS

1. **Saída de Threads:** as threads normalmente são encerradas chamando `pthread_exit()`. Essa função permite que uma thread seja encerrada de forma limpa, executando a limpeza necessária e permitindo que ela envie um valor de retorno para qualquer thread que esteja aguardando por ela.
2. **Limpeza de Threads:** ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada. Ela gerencia a remoção de todas as estruturas associadas à thread. A função desaloca as portas de thread do Mach (Mach é o subsistema de comunicação do kernel XNU) e chama `bsdthread_terminate`, uma syscall que remove as estruturas no nível do kernel associadas à thread.

#### Mecanismos de sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS fornece várias primitivas de sincronização. Elas são essenciais em ambientes multi-threading para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
- **Mutex regular (Signature: 0x4D555458):** mutex padrão com um footprint de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a signature).
- **Fast Mutex (Signature: 0x4d55545A):** semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes de tamanho.
2. **Variáveis de condição:**
- Usadas para aguardar a ocorrência de determinadas condições, com um tamanho de 44 bytes (40 bytes mais uma signature de 4 bytes).
- **Atributos de variáveis de condição (Signature: 0x434e4441):** atributos de configuração para variáveis de condição, com 12 bytes de tamanho.
3. **Variável Once (Signature: 0x4f4e4345):**
- Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Read-Write Locks:**
- Permitem múltiplos readers ou um writer por vez, facilitando o acesso eficiente a dados compartilhados.
- **Read Write Lock (Signature: 0x52574c4b):** possui 196 bytes.
- **Atributos de Read Write Lock (Signature: 0x52574c41):** atributos para read-write locks, com 20 bytes de tamanho.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar overflows.

### Variáveis locais de Thread (TLV)

As **Thread Local Variables (TLV)** no contexto de arquivos Mach-O (o formato dos executáveis no macOS) são usadas para declarar variáveis específicas de **cada thread** em uma aplicação multi-threaded. Isso garante que cada thread tenha sua própria instância separada de uma variável, fornecendo uma forma de evitar conflitos e manter a integridade dos dados sem a necessidade de mecanismos explícitos de sincronização, como mutexes.

Em C e linguagens relacionadas, você pode declarar uma variável local de thread usando a palavra-chave **`__thread`**. Veja como isso funciona no seu exemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este trecho define `tlv_var` como uma variável local à thread. Cada thread que executa este código terá sua própria `tlv_var`, e as alterações que uma thread fizer em `tlv_var` não afetarão a `tlv_var` de outra thread.

No binário Mach-O, os dados relacionados às variáveis locais à thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: esta seção contém os metadados sobre as variáveis locais à thread, como seus tipos e o status de inicialização.
- **`__DATA.__thread_bss`**: esta seção é usada para variáveis locais à thread que não foram inicializadas explicitamente. Ela faz parte da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis locais à thread quando uma thread é encerrada. Essa API permite **registrar destrutores** — funções especiais que limpam os dados locais à thread quando uma thread termina.

### Prioridades de Thread

Entender as prioridades de thread envolve observar como o sistema operacional decide quais threads executar e quando executá-las. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas semelhantes ao Unix, isso é gerenciado usando conceitos como `nice`, `renice` e classes de Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
- O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo possui um valor `nice` entre -20 (a prioridade mais alta) e 19 (a prioridade mais baixa). O valor `nice` padrão quando um processo é criado normalmente é 0.
- Um valor `nice` menor (mais próximo de -20) torna um processo mais "egoísta", concedendo-lhe mais tempo de CPU em comparação com outros processos que possuem valores `nice` mais altos.
2. **Renice:**
- `renice` é um comando usado para alterar o valor `nice` de um processo já em execução. Ele pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo a alocação de tempo de CPU com base nos novos valores `nice`.
- Por exemplo, se um processo precisar temporariamente de mais recursos de CPU, você poderá diminuir seu valor `nice` usando `renice`.

#### Classes de Quality of Service (QoS)

As classes de QoS são uma abordagem mais moderna para gerenciar prioridades de thread, especialmente em sistemas como o macOS, que oferecem suporte ao **Grand Central Dispatch (GCD)**. As classes de QoS permitem que desenvolvedores **categorizem** o trabalho em diferentes níveis com base em sua importância ou urgência. O macOS gerencia automaticamente a priorização das threads com base nessas classes de QoS:

1. **User Interactive:**
- Esta classe é destinada a tarefas que estão interagindo com o usuário ou que exigem resultados imediatos para proporcionar uma boa experiência de uso. Essas tarefas recebem a prioridade mais alta para manter a interface responsiva (por exemplo, animações ou tratamento de eventos).
2. **User Initiated:**
- Tarefas iniciadas pelo usuário, para as quais ele espera resultados imediatos, como abrir um documento ou clicar em um botão que exige cálculos. Elas possuem alta prioridade, mas ficam abaixo de User Interactive.
3. **Utility:**
- Essas tarefas são de longa duração e normalmente exibem um indicador de progresso (por exemplo, baixar arquivos ou importar dados). Elas têm prioridade menor que as tarefas iniciadas pelo usuário e não precisam terminar imediatamente.
4. **Background:**
- Esta classe é destinada a tarefas executadas em segundo plano e que não são visíveis para o usuário. Elas podem incluir tarefas como indexação, sincronização ou backups. Possuem a menor prioridade e impacto mínimo no desempenho do sistema.

Usando classes de QoS, os desenvolvedores não precisam gerenciar números exatos de prioridade, mas apenas se concentrar na natureza da tarefa; o sistema otimiza os recursos de CPU de acordo com isso.

Além disso, existem diferentes **políticas de agendamento de threads** que permitem especificar um conjunto de parâmetros de agendamento que o scheduler levará em consideração. Isso pode ser feito usando `thread_policy_[set/get]`. Isso pode ser útil em ataques de race condition.

## Abuso de Processos no MacOS

O MacOS, assim como qualquer outro sistema operacional, fornece vários métodos e mecanismos para que **processos interajam, se comuniquem e compartilhem dados**. Embora essas técnicas sejam essenciais para o funcionamento eficiente do sistema, elas também podem ser abusadas por threat actors para **realizar atividades maliciosas**.

### Library Injection

Library Injection é uma técnica na qual um invasor **força um processo a carregar uma biblioteca maliciosa**. Depois de injetada, a biblioteca é executada no contexto do processo-alvo, fornecendo ao invasor as mesmas permissões e o mesmo acesso que o processo possui.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking envolve **interceptar chamadas de funções** ou mensagens dentro de um código de software. Ao fazer hooking de funções, um invasor pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo obter controle sobre o fluxo de execução.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) refere-se aos diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora IPC seja fundamental para muitas aplicações legítimas, também pode ser usado indevidamente para subverter o isolamento entre processos, realizar leak de informações sensíveis ou executar ações não autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplicações Electron executadas com determinadas variáveis de ambiente podem estar vulneráveis a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **man in the browser attack**, permitindo roubar teclas digitadas, tráfego, cookies, injetar scripts em páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de uma aplicação. No entanto, eles podem **executar comandos arbitrários** e o **Gatekeeper não impede** que uma aplicação já executada seja executada novamente se um **arquivo NIB for modificado**. Portanto, eles podem ser usados para fazer programas arbitrários executarem comandos arbitrários:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

É possível abusar de determinados recursos do java (como a variável de ambiente **`_JAVA_OPTS`**) para fazer uma aplicação java executar **código/comandos arbitrários**.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

É possível injetar código em aplicações .Net **abusando da funcionalidade de debugging do .Net** (não protegida por mecanismos de proteção do macOS, como runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Confira diferentes opções para fazer um script Perl executar código arbitrário em:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Também é possível abusar das variáveis de ambiente do ruby para fazer scripts arbitrários executarem código arbitrário:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Se a variável de ambiente **`PYTHONINSPECT`** estiver definida, o processo python entrará em uma CLI do python assim que terminar. Também é possível usar **`PYTHONSTARTUP`** para indicar um script python a ser executado no início de uma sessão interativa.\
No entanto, observe que o script **`PYTHONSTARTUP`** não será executado quando **`PYTHONINSPECT`** criar a sessão interativa.

Outras variáveis de ambiente, como **`PYTHONPATH`** e **`PYTHONHOME`**, também podem ser úteis para fazer um comando python executar código arbitrário.

Observe que executáveis compilados com **`pyinstaller`** não usarão essas variáveis de ambiente, mesmo quando estiverem sendo executados usando um python incorporado.

> [!CAUTION]
> No geral, não consegui encontrar uma maneira de fazer o python executar código arbitrário abusando de variáveis de ambiente.\
> No entanto, a maioria das pessoas instala o pyhton usando **Hombrew**, que instalará o pyhton em um **local gravável** para o usuário admin padrão. Você pode sequestrá-lo com algo como:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Até mesmo o **root** executará este código ao executar python.


## Detecção

### Shield

[**Shield**](https://github.com/theevilbit/Shield) é uma aplicação open source baseada em **EndpointSecurity** que detecta e bloqueia process injection. Ela é uma boa referência sobre quais sinais são realmente observáveis a partir do ES, pois gera alertas para:<sup>[[1]](#references)[[2]](#references)</sup>

- **Variáveis de ambiente de injection** na execução de processos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chamadas **`task_for_pid`** — um processo solicitando a task port de outro, o que é um pré-requisito para injetar código nele.
- **Argumentos de debugging do Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, que iniciam uma aplicação Electron em modo de debug e permitem que qualquer pessoa se conecte a ela e execute código.<sup>[[3]](#references)</sup>
- **Criação de symlink/hardlink entre níveis de privilégio** — o primitivo clássico de "criar um link como usuário normal e apontá-lo para um local privilegiado". Observe que **symlinks podem gerar alertas, mas não podem ser bloqueados**: o EndpointSecurity não expõe o destino do link antes da criação.

### Chamadas realizadas por outros processos

Nesta [**publicação do blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode encontrar informações sobre como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.<sup>[[4]](#references)</sup>

Observe que, para chamar essa função, você precisa ter **o mesmo uid** do usuário que executa o processo ou ser **root** (e ela retorna informações sobre o processo, não uma forma de injetar código).

## Referências

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
