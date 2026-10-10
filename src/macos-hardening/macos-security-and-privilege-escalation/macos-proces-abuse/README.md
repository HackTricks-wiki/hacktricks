# Abuso de processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas sobre processos

Um processo é uma instância de um executável em execução. No entanto, os processos não executam código; quem o faz são as threads. Portanto, **os processos são apenas contêineres para threads em execução**, que fornecem memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criava uma cópia exata do processo atual; em seguida, o **processo filho** geralmente chamava **`execve`** para carregar o novo executável e executá-lo. Depois, **`vfork`** foi introduzido para tornar esse processo mais rápido, sem copiar memória.\
Em seguida, **`posix_spawn`** foi introduzido, combinando **`vfork`** e **`execve`** em uma única chamada e aceitando flags:

- `POSIX_SPAWN_RESETIDS`: Redefine os IDs efetivos para os IDs reais
- `POSIX_SPAWN_SETPGROUP`: Define a associação ao grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Define o comportamento padrão dos sinais
- `POSIX_SPAWN_SETSIGMASK`: Define a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executa no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa o alocador Nano da libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` em segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fecha todos os descritores de arquivo por padrão em exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiza os bits altos do deslocamento do ASLR

Além disso, `posix_spawn` aceita configurações **`posix_spawnattr`**, que controlam aspectos do processo criado, e entradas **`posix_spawn_file_actions`**, que modificam descritores de arquivo.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai morreu, o novo pai é o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()`; até isso acontecer, o filho permanece em estado zumbi, ainda listado, mas sem consumir recursos.

### PIDs

PIDs, ou identificadores de processo, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonicamente e **nunca dão a volta** (para evitar abusos).

### Grupos de processos, sessões e coalizões

**Processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, comandos em um script de shell ficam no mesmo grupo de processos, permitindo **enviar sinais a todos juntos**, usando `kill`, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são inseridos nessa sessão, a menos que iniciem sua própria sessão.

Coalition é outra forma de agrupar processos no Darwin. Um processo que entra em uma coalition pode acessar recursos do pool, compartilhar um ledger ou estar sujeito ao Jetsam. As coalitions têm diferentes funções: Leader, serviço XPC, Extension.

### Credenciais e personas

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o ID de usuário e de grupo se o binário tiver o bit `setuid/setgid`.\
Há várias funções para **definir novos uids/gids**.

A chamada de sistema **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume de uma só vez seu uid, gid e associações a grupos. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a estrutura:

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

## Informações básicas sobre threads

1. **POSIX Threads (pthreads):** o macOS oferece suporte a threads POSIX (`pthreads`), que fazem parte de uma API padrão de threading para C/C++. A implementação de pthreads no macOS está em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread`, disponível publicamente. Essa biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criação de threads:** a função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, uma chamada de sistema de baixo nível específica do kernel XNU (o kernel no qual o macOS se baseia). Essa chamada de sistema recebe vários flags derivados de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de agendamento e tamanho da stack.
   - **Tamanho padrão da stack:** o tamanho padrão da stack para novas threads é 512 KB, o que é suficiente para operações típicas, mas pode ser ajustado por meio dos atributos da thread, caso seja necessário mais ou menos espaço.
3. **Inicialização de threads:** a função `__pthread_init()` é essencial durante a configuração da thread. Ela usa o argumento `env[]` para analisar variáveis de ambiente, que podem incluir detalhes sobre a localização e o tamanho da stack.

#### Encerramento de threads no macOS

1. **Saída de threads:** normalmente, as threads são encerradas com uma chamada a `pthread_exit()`. Essa função permite que uma thread saia corretamente, realizando a limpeza necessária e permitindo que ela envie um valor de retorno a qualquer thread que aguarde sua conclusão.
2. **Limpeza de threads:** ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada para remover todas as estruturas associadas à thread. Ela desaloca as portas de thread do Mach (Mach é o subsistema de comunicação do kernel XNU) e chama `bsdthread_terminate`, uma syscall que remove as estruturas no nível do kernel associadas à thread.

#### Mecanismos de sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS oferece várias primitivas de sincronização. Elas são essenciais em ambientes multithread para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
   - **Mutex regular (assinatura: 0x4D555458):** mutex padrão com uma ocupação de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a assinatura).
   - **Mutex rápido (assinatura: 0x4d55545A):** semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes.
2. **Variáveis de condição:**
   - Usadas para aguardar a ocorrência de determinadas condições, com um tamanho de 44 bytes (40 bytes mais uma assinatura de 4 bytes).
   - **Atributos de variável de condição (assinatura: 0x434e4441):** atributos de configuração para variáveis de condição, com tamanho de 12 bytes.
3. **Variável Once (assinatura: 0x4f4e4345):**
   - Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Locks de leitura e escrita:**
   - Permitem vários leitores ou um escritor por vez, facilitando o acesso eficiente aos dados compartilhados.
   - **Lock de leitura e escrita (assinatura: 0x52574c4b):** tem 196 bytes.
   - **Atributos de lock de leitura e escrita (assinatura: 0x52574c41):** atributos para locks de leitura e escrita, com tamanho de 20 bytes.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar overflow.

### Variáveis locais de thread (TLV)

**Variáveis locais de thread (TLV)**, no contexto de arquivos Mach-O (o formato dos executáveis no macOS), são usadas para declarar variáveis específicas de **cada thread** em um aplicativo multithread. Isso garante que cada thread tenha sua própria instância independente de uma variável, oferecendo uma forma de evitar conflitos e manter a integridade dos dados sem precisar de mecanismos explícitos de sincronização, como mutexes.

Em C e linguagens relacionadas, é possível declarar uma variável local de thread usando a palavra-chave **`__thread`**. Veja como funciona no exemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este trecho define `tlv_var` como uma variável local à thread. Cada thread que executar este código terá sua própria `tlv_var`, e as alterações feitas por uma thread em `tlv_var` não afetarão a `tlv_var` de outra thread.

No binário Mach-O, os dados relacionados às variáveis locais à thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: Esta seção contém os metadados das variáveis locais à thread, como seus tipos e o status de inicialização.
- **`__DATA.__thread_bss`**: Esta seção é usada para variáveis locais à thread que não são inicializadas explicitamente. É uma parte da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica, chamada **`tlv_atexit`**, para gerenciar variáveis locais à thread quando uma thread é encerrada. Essa API permite **registrar destrutores** — funções especiais que limpam os dados locais à thread quando ela termina.

### Prioridades de Thread

Para entender as prioridades de thread, é preciso analisar como o sistema operacional decide quais threads executar e quando. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas do tipo Unix, isso é gerenciado com conceitos como `nice`, `renice` e classes Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
   - O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo tem um valor `nice` entre -20 (prioridade mais alta) e 19 (prioridade mais baixa). O valor `nice` padrão ao criar um processo costuma ser 0.
   - Um valor `nice` menor (mais próximo de -20) torna o processo mais “egoísta”, concedendo-lhe mais tempo de CPU em comparação com outros processos que têm valores `nice` maiores.
2. **Renice:**
   - `renice` é um comando usado para alterar o valor `nice` de um processo em execução. Ele pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo a alocação de tempo de CPU de acordo com os novos valores `nice`.
   - Por exemplo, se um processo precisar temporariamente de mais recursos de CPU, você pode diminuir seu valor `nice` usando `renice`.

#### Classes Quality of Service (QoS)

As classes QoS são uma abordagem mais moderna para gerenciar prioridades de thread, especialmente em sistemas como o macOS, que oferecem suporte ao **Grand Central Dispatch (GCD)**. As classes QoS permitem que desenvolvedores **categorize**m o trabalho em diferentes níveis, de acordo com sua importância ou urgência. O macOS gerencia automaticamente a prioridade das threads com base nessas classes QoS:

1. **User Interactive:**
   - Esta classe é destinada a tarefas que estão interagindo com o usuário ou precisam fornecer resultados imediatos para garantir uma boa experiência. Essas tarefas recebem a prioridade mais alta para manter a interface responsiva (por exemplo, animações ou tratamento de eventos).
2. **User Initiated:**
   - Tarefas iniciadas pelo usuário para as quais se esperam resultados imediatos, como abrir um documento ou clicar em um botão que exige cálculos. Elas têm prioridade alta, mas inferior à de User Interactive.
3. **Utility:**
   - Essas tarefas são de longa duração e geralmente exibem um indicador de progresso (por exemplo, baixar arquivos ou importar dados). Elas têm prioridade menor do que as tarefas iniciadas pelo usuário e não precisam terminar imediatamente.
4. **Background:**
   - Esta classe é destinada a tarefas executadas em segundo plano e que não são visíveis para o usuário. Podem ser tarefas como indexação, sincronização ou backups. Elas têm a prioridade mais baixa e impacto mínimo no desempenho do sistema.

Com as classes QoS, os desenvolvedores não precisam gerenciar os números exatos de prioridade; em vez disso, podem se concentrar na natureza da tarefa, enquanto o sistema otimiza os recursos de CPU adequadamente.

Além disso, há diferentes **políticas de escalonamento de threads**, que permitem especificar um conjunto de parâmetros de escalonamento que o escalonador levará em conta. Isso pode ser feito usando `thread_policy_[set/get]`. Esse recurso pode ser útil em ataques de race condition.

## macOS Process Abuse

O macOS oferece vários mecanismos para que **processos interajam, se comuniquem e compartilhem dados**. Embora esses mecanismos sejam essenciais para o funcionamento normal do sistema, atacantes podem abusar deles para realizar injeção, execução de código ou acesso a dados.

### Library Injection

Library Injection é uma técnica na qual um atacante **força um processo a carregar uma biblioteca maliciosa**. Depois de injetada, a biblioteca é executada no contexto do processo-alvo, dando ao atacante as mesmas permissões e o mesmo acesso que o processo.

{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste em **interceptar chamadas de função** ou mensagens dentro de um código de software. Ao fazer hooking de funções, um atacante pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo assumir o controle do fluxo de execução.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) refere-se aos diferentes métodos usados por processos separados para **compartilhar e trocar dados**. Embora o IPC seja fundamental para muitos aplicativos legítimos, ele também pode ser usado indevidamente para subverter o isolamento entre processos, vazar informações sensíveis ou realizar ações não autorizadas.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplicativos Electron executados com variáveis de ambiente específicas podem estar vulneráveis à injeção de processos:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **man in the browser attack**, permitindo roubar teclas digitadas, tráfego e cookies, injetar scripts em páginas...

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de um aplicativo. No entanto, eles podem **executar comandos arbitrários**, e o **Gatekeeper não impede** a execução de um aplicativo que já foi executado caso um **arquivo NIB seja modificado**. Portanto, eles podem ser usados para fazer programas arbitrários executarem comandos arbitrários:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

É possível injetar opções da JVM por meio de **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`** e carregar um agente Java ou nativo antes de o aplicativo iniciar.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** pré-carrega JavaScript controlado pelo atacante usando `--require` (arquivo) ou `--import data:text/javascript,…` (sem arquivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carrega um módulo em um REPL interativo, e **`ELECTRON_RUN_AS_NODE`** reativa tudo isso em binários Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

É possível injetar código em aplicativos .NET por meio de **`DOTNET_STARTUP_HOOKS`**, antes de `Main`, ou abusando da funcionalidade de depuração do .NET quando os pré-requisitos estão presentes.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

O Bash não interativo lê **`BASH_ENV`**; shells POSIX interativos leem **`ENV`**; o zsh lê **`$ZDOTDIR/.zshenv`**; e o fish lê configurações em **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Cada um pode executar um arquivo de inicialização controlado antes do comando pretendido. O Bash também executa uma substituição de comando inserida em **`PS4`** sempre que o xtrace está ativado (por exemplo, por meio de **`SHELLOPTS=xtrace`** herdado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** podem carregar uma configuração PHP controlada cujo **`auto_prepend_file`** é executado antes do script-alvo.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

O interpretador Lua independente executa código ou um `@file` de **`LUA_INIT`** (ou de sua variante específica da versão) antes de processar o script-alvo.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** redirecionam para perfis de inicialização que contêm código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, combinados com um caminho de biblioteca R, podem carregar automaticamente um pacote instalado.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redireciona para o depot cujo `config/startup.jl` é executado automaticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** podem injetar uma expressão Erlang VM **`-eval`** sem exigir um arquivo de payload; workloads Elixir geralmente iniciam a mesma VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** redirecionam para scripts de inicialização do Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` é um aplicativo .NET multiplataforma, então várias variáveis de ambiente permitem a execução antes do comando: **`XDG_CONFIG_HOME`** redireciona para os scripts de perfil executados na inicialização, **`PSModulePath`** permite sequestrar o carregamento automático de módulos (um arquivo `.psm1` plantado é executado no momento da importação e pode substituir cmdlets integrados), e as variáveis .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** carregam código do atacante no processo antes de `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Confira diferentes opções para fazer um script Perl executar código arbitrário em:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Também é possível abusar das variáveis de ambiente do Ruby (**`RUBYOPT`**, **`RUBYLIB`**) para fazer scripts arbitrários executarem código arbitrário:

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

A cadeia da biblioteca padrão **`PYTHONWARNINGS`** e **`BROWSER`** pode executar um comando durante a análise dos filtros de aviso. Uma alternativa baseada em arquivo coloca `sitecustomize.py` em **`PYTHONPATH`**, para que a inicialização normal de `site` o importe antes do script-alvo. **`PYTHONBREAKPOINT`** executa um callable/módulo escolhido quando o código chega a `breakpoint()`. Variáveis exclusivas do modo interativo, como **`PYTHONSTARTUP`**, têm aplicabilidade mais restrita.

Observe que executáveis compilados com **`pyinstaller`** não usam essas variáveis de ambiente, mesmo quando estão sendo executados com um Python incorporado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (e sua alternativa `EXINIT`) são executados como comandos Ex durante uma inicialização normal; portanto, `:!cmd` / `:call system(...)` permitem a execução de código quando uma vítima abre o Vim/Neovim com um ambiente controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separadamente, o Homebrew costuma instalar o Python em `/opt/homebrew`, onde membros do grupo local `admin` podem conseguir substituir o launcher. Isso é um sequestro de binário gravável, não uma injeção por variável de ambiente; verifique a propriedade e as ACLs antes de considerá-lo explorável.

## Detecção

### Shield

[**Shield**](https://github.com/theevilbit/Shield) é um aplicativo de código aberto baseado em **EndpointSecurity** que detecta e bloqueia injeção de processos. É uma boa referência para saber quais sinais são observáveis por meio do Endpoint Security, pois gera alertas para:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variáveis de ambiente de injeção** na execução de processos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chamadas **`task_for_pid`** — um processo solicitando a task port de outro, pré-requisito para injetar código nele.
- **Argumentos de depuração do Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, que iniciam um aplicativo Electron em modo de depuração e permitem que qualquer pessoa se conecte a ele e execute código.<sup>[[3]](#references)</sup>
- **Criação de symlinks/hardlinks entre níveis de privilégio** — o mecanismo clássico de “criar um link como usuário normal e apontá-lo para um local privilegiado”. Observe que **symlinks podem gerar alertas, mas não podem ser bloqueados**: o EndpointSecurity não expõe o destino do link antes de sua criação.

### Chamadas feitas por outros processos

Nesta [**publicação de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode descobrir como usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.<sup>[[4]](#references)</sup>

Observe que, para chamar essa função, é necessário ter o **mesmo uid** do processo em execução ou ser **root** (e ela retorna informações sobre o processo, não um meio de injetar código).

## References

- [1] [Shield — detecção de injeção de processos no macOS de código aberto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por que aplicativos Electron não podem armazenar seus segredos de forma confidencial: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detectando modificações de tasks](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
