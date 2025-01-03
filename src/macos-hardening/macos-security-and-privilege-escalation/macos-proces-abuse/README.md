# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas sobre Processos

Um processo é uma instância de um executável em execução, no entanto, os processos não executam código, esses são threads. Portanto, **os processos são apenas contêineres para threads em execução** fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criaria uma cópia exata do processo atual e então o **processo filho** geralmente chamaria **`execve`** para carregar o novo executável e executá-lo. Então, **`vfork`** foi introduzido para tornar esse processo mais rápido sem qualquer cópia de memória.\
Depois, **`posix_spawn`** foi introduzido combinando **`vfork`** e **`execve`** em uma única chamada e aceitando flags:

- `POSIX_SPAWN_RESETIDS`: Redefinir ids efetivos para ids reais
- `POSIX_SPAWN_SETPGROUP`: Definir afiliação do grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Definir comportamento padrão do sinal
- `POSIX_SPAWN_SETSIGMASK`: Definir máscara de sinal
- `POSIX_SPAWN_SETEXEC`: Execução no mesmo processo (como `execve` com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar o alocador Nano da libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` em segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fechar todas as descrições de arquivo em exec(2) por padrão
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizar os bits altos do deslizamento ASLR

Além disso, `posix_spawn` permite especificar um array de **`posix_spawnattr`** que controla alguns aspectos do processo gerado, e **`posix_spawn_file_actions`** para modificar o estado dos descritores.

Quando um processo morre, ele envia o **código de retorno para o processo pai** (se o pai morreu, o novo pai é o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()` e até que isso aconteça, o filho permanece em um estado zumbi onde ainda está listado, mas não consome recursos.

### PIDs

PIDs, identificadores de processo, identificam um processo único. No XNU, os **PIDs** são de **64 bits** aumentando monotonamente e **nunca se reiniciam** (para evitar abusos).

### Grupos de Processos, Sessões e Coalizões

**Processos** podem ser inseridos em **grupos** para facilitar seu manuseio. Por exemplo, comandos em um script de shell estarão no mesmo grupo de processos, então é possível **sinalizá-los juntos** usando kill, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados dentro da sessão, a menos que iniciem sua própria sessão.

Coalizão é outra maneira de agrupar processos no Darwin. Um processo que se junta a uma coalizão permite acessar recursos do pool, compartilhando um livro-razão ou enfrentando Jetsam. As coalizões têm diferentes papéis: Líder, serviço XPC, Extensão.

### Credenciais e Personas

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível mudar o id do usuário e do grupo se o binário tiver o bit `setuid/setgid`.\
Existem várias funções para **definir novos uids/gids**.

A syscall **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações de grupo **de uma só vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) é possível encontrar a struct:
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
## Informações Básicas sobre Threads

1. **POSIX Threads (pthreads):** O macOS suporta threads POSIX (`pthreads`), que fazem parte de uma API de threading padrão para C/C++. A implementação de pthreads no macOS é encontrada em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread` disponível publicamente. Esta biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criando Threads:** A função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, que é uma chamada de sistema de nível inferior específica para o kernel XNU (o kernel no qual o macOS é baseado). Esta chamada de sistema aceita várias flags derivadas de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de agendamento e tamanho da pilha.
- **Tamanho da Pilha Padrão:** O tamanho da pilha padrão para novas threads é de 512 KB, o que é suficiente para operações típicas, mas pode ser ajustado através de atributos de thread se mais ou menos espaço for necessário.
3. **Inicialização da Thread:** A função `__pthread_init()` é crucial durante a configuração da thread, utilizando o argumento `env[]` para analisar variáveis de ambiente que podem incluir detalhes sobre a localização e o tamanho da pilha.

#### Terminação de Threads no macOS

1. **Saindo de Threads:** As threads são tipicamente terminadas chamando `pthread_exit()`. Esta função permite que uma thread saia de forma limpa, realizando a limpeza necessária e permitindo que a thread envie um valor de retorno de volta para qualquer thread que a tenha juntado.
2. **Limpeza da Thread:** Ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada, que lida com a remoção de todas as estruturas de thread associadas. Ela desaloca portas de thread Mach (Mach é o subsistema de comunicação no kernel XNU) e chama `bsdthread_terminate`, uma syscall que remove as estruturas de nível de kernel associadas à thread.

#### Mecanismos de Sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS fornece várias primitivas de sincronização. Estas são críticas em ambientes de multi-threading para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
- **Mutex Regular (Assinatura: 0x4D555458):** Mutex padrão com uma pegada de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a assinatura).
- **Mutex Rápido (Assinatura: 0x4d55545A):** Semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes de tamanho.
2. **Variáveis de Condição:**
- Usadas para esperar que certas condições ocorram, com um tamanho de 44 bytes (40 bytes mais uma assinatura de 4 bytes).
- **Atributos de Variável de Condição (Assinatura: 0x434e4441):** Atributos de configuração para variáveis de condição, com tamanho de 12 bytes.
3. **Variável Once (Assinatura: 0x4f4e4345):**
- Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Locks de Leitura-Gravação:**
- Permite múltiplos leitores ou um escritor por vez, facilitando o acesso eficiente a dados compartilhados.
- **Lock de Leitura-Gravação (Assinatura: 0x52574c4b):** Tamanho de 196 bytes.
- **Atributos de Lock de Leitura-Gravação (Assinatura: 0x52574c41):** Atributos para locks de leitura-gravação, com 20 bytes de tamanho.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar estouros.

### Variáveis Locais de Thread (TLV)

**Variáveis Locais de Thread (TLV)** no contexto de arquivos Mach-O (o formato para executáveis no macOS) são usadas para declarar variáveis que são específicas para **cada thread** em uma aplicação multi-threaded. Isso garante que cada thread tenha sua própria instância separada de uma variável, proporcionando uma maneira de evitar conflitos e manter a integridade dos dados sem a necessidade de mecanismos de sincronização explícitos, como mutexes.

Em C e linguagens relacionadas, você pode declarar uma variável local de thread usando a palavra-chave **`__thread`**. Aqui está como funciona em seu exemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este trecho define `tlv_var` como uma variável local de thread. Cada thread que executa este código terá seu próprio `tlv_var`, e as alterações que uma thread faz em `tlv_var` não afetarão `tlv_var` em outra thread.

No binário Mach-O, os dados relacionados a variáveis locais de thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: Esta seção contém os metadados sobre as variáveis locais de thread, como seus tipos e status de inicialização.
- **`__DATA.__thread_bss`**: Esta seção é usada para variáveis locais de thread que não são explicitamente inicializadas. É uma parte da memória reservada para dados inicializados com zero.

Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis locais de thread quando uma thread sai. Esta API permite que você **registre destrutores**—funções especiais que limpam os dados locais de thread quando uma thread termina.

### Prioridades de Thread

Entender as prioridades de thread envolve observar como o sistema operacional decide quais threads executar e quando. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas semelhantes ao Unix, isso é tratado usando conceitos como `nice`, `renice` e classes de Qualidade de Serviço (QoS).

#### Nice e Renice

1. **Nice:**
- O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo tem um valor nice que varia de -20 (a maior prioridade) a 19 (a menor prioridade). O valor nice padrão quando um processo é criado é tipicamente 0.
- Um valor nice mais baixo (mais próximo de -20) torna um processo mais "egoísta", dando-lhe mais tempo de CPU em comparação com outros processos com valores nice mais altos.
2. **Renice:**
- `renice` é um comando usado para alterar o valor nice de um processo que já está em execução. Isso pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo sua alocação de tempo de CPU com base em novos valores nice.
- Por exemplo, se um processo precisar de mais recursos de CPU temporariamente, você pode diminuir seu valor nice usando `renice`.

#### Classes de Qualidade de Serviço (QoS)

As classes de QoS são uma abordagem mais moderna para lidar com prioridades de thread, particularmente em sistemas como o macOS que suportam **Grand Central Dispatch (GCD)**. As classes de QoS permitem que os desenvolvedores **classifiquem** o trabalho em diferentes níveis com base em sua importância ou urgência. O macOS gerencia a priorização de threads automaticamente com base nessas classes de QoS:

1. **Interativo do Usuário:**
- Esta classe é para tarefas que estão atualmente interagindo com o usuário ou requerem resultados imediatos para proporcionar uma boa experiência ao usuário. Essas tarefas recebem a maior prioridade para manter a interface responsiva (por exemplo, animações ou manipulação de eventos).
2. **Iniciado pelo Usuário:**
- Tarefas que o usuário inicia e espera resultados imediatos, como abrir um documento ou clicar em um botão que requer cálculos. Estas têm alta prioridade, mas abaixo da interativa do usuário.
3. **Utilitário:**
- Essas tarefas são de longa duração e normalmente mostram um indicador de progresso (por exemplo, download de arquivos, importação de dados). Elas têm prioridade inferior em relação às tarefas iniciadas pelo usuário e não precisam ser concluídas imediatamente.
4. **Fundo:**
- Esta classe é para tarefas que operam em segundo plano e não são visíveis para o usuário. Estas podem ser tarefas como indexação, sincronização ou backups. Elas têm a menor prioridade e impacto mínimo no desempenho do sistema.

Usando classes de QoS, os desenvolvedores não precisam gerenciar os números de prioridade exatos, mas sim se concentrar na natureza da tarefa, e o sistema otimiza os recursos de CPU de acordo.

Além disso, existem diferentes **políticas de agendamento de thread** que fluem para especificar um conjunto de parâmetros de agendamento que o escalonador levará em consideração. Isso pode ser feito usando `thread_policy_[set/get]`. Isso pode ser útil em ataques de condição de corrida.

## Abuso de Processos no MacOS

O MacOS, como qualquer outro sistema operacional, fornece uma variedade de métodos e mecanismos para **processos interagirem, se comunicarem e compartilharem dados**. Embora essas técnicas sejam essenciais para o funcionamento eficiente do sistema, elas também podem ser abusadas por atores maliciosos para **realizar atividades maliciosas**.

### Injeção de Biblioteca

A Injeção de Biblioteca é uma técnica em que um atacante **força um processo a carregar uma biblioteca maliciosa**. Uma vez injetada, a biblioteca é executada no contexto do processo alvo, fornecendo ao atacante as mesmas permissões e acesso que o processo.

{{#ref}}
macos-library-injection/
{{#endref}}

### Hooking de Função

O Hooking de Função envolve **interceptar chamadas de função** ou mensagens dentro de um código de software. Ao hookear funções, um atacante pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo ganhar controle sobre o fluxo de execução.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### Comunicação entre Processos

A Comunicação entre Processos (IPC) refere-se a diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora a IPC seja fundamental para muitas aplicações legítimas, ela também pode ser mal utilizada para subverter a isolação de processos, vazar informações sensíveis ou realizar ações não autorizadas.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injeção de Aplicações Electron

Aplicações Electron executadas com variáveis de ambiente específicas podem ser vulneráveis à injeção de processos:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injeção de Chromium

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **ataque man in the browser** permitindo roubar pressionamentos de tecla, tráfego, cookies, injetar scripts em páginas...:

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### NIB Sujo

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de um aplicativo. No entanto, eles podem **executar comandos arbitrários** e **o Gatekeeper não impede** que um aplicativo já executado seja executado se um **arquivo NIB for modificado**. Portanto, eles poderiam ser usados para fazer programas arbitrários executarem comandos arbitrários:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injeção de Aplicações Java

É possível abusar de certas capacidades do Java (como a variável de ambiente **`_JAVA_OPTS`**) para fazer um aplicativo Java executar **código/comandos arbitrários**.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injeção de Aplicações .Net

É possível injetar código em aplicações .Net **abusando da funcionalidade de depuração do .Net** (não protegida por proteções do macOS, como endurecimento em tempo de execução).

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Injeção de Perl

Verifique diferentes opções para fazer um script Perl executar código arbitrário em:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Injeção de Ruby

Também é possível abusar de variáveis de ambiente Ruby para fazer scripts arbitrários executarem código arbitrário:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Injeção de Python

Se a variável de ambiente **`PYTHONINSPECT`** estiver definida, o processo Python entrará em um CLI Python assim que terminar. Também é possível usar **`PYTHONSTARTUP`** para indicar um script Python a ser executado no início de uma sessão interativa.\
No entanto, observe que o script **`PYTHONSTARTUP`** não será executado quando **`PYTHONINSPECT`** criar a sessão interativa.

Outras variáveis de ambiente, como **`PYTHONPATH`** e **`PYTHONHOME`**, também podem ser úteis para fazer um comando Python executar código arbitrário.

Observe que executáveis compilados com **`pyinstaller`** não usarão essas variáveis ambientais, mesmo que estejam sendo executados usando um Python embutido.

> [!CAUTION]
> No geral, não consegui encontrar uma maneira de fazer o Python executar código arbitrário abusando de variáveis de ambiente.\
> No entanto, a maioria das pessoas instala Python usando **Homebrew**, que instalará Python em um **local gravável** para o usuário admin padrão. Você pode sequestrá-lo com algo como:
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Código de sequestro extra
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Mesmo **root** executará este código ao rodar o Python.

## Detecção

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) é um aplicativo de código aberto que pode **detectar e bloquear ações de injeção de processos**:

- Usando **Variáveis Ambientais**: Ele monitorará a presença de qualquer uma das seguintes variáveis ambientais: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
- Usando chamadas **`task_for_pid`**: Para descobrir quando um processo deseja obter o **port de tarefa de outro**, o que permite injetar código no processo.
- **Parâmetros de aplicativos Electron**: Alguém pode usar os argumentos de linha de comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** para iniciar um aplicativo Electron em modo de depuração e, assim, injetar código nele.
- Usando **symlinks** ou **hardlinks**: Normalmente, o abuso mais comum é **colocar um link com nossos privilégios de usuário** e **apontá-lo para um local de maior privilégio**. A detecção é muito simples tanto para hardlinks quanto para symlinks. Se o processo que cria o link tiver um **nível de privilégio diferente** do arquivo de destino, criamos um **alerta**. Infelizmente, no caso de symlinks, o bloqueio não é possível, pois não temos informações sobre o destino do link antes da criação. Esta é uma limitação do framework EndpointSecurity da Apple.

### Chamadas feitas por outros processos

Em [**este post do blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) você pode encontrar como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.

Observe que, para chamar essa função, você precisa ser **o mesmo uid** que o que está executando o processo ou **root** (e ela retorna informações sobre o processo, não uma maneira de injetar código).

## Referências

- [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
- [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{{#include ../../../banners/hacktricks-training.md}}
