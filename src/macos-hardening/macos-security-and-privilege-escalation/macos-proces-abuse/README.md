# Abuso de processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas sobre processos

Um processo é uma instância de um executável em execução. No entanto, os processos não executam código; quem faz isso são as threads. Portanto, **os processos são apenas contêineres para threads em execução**, fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criava uma cópia exata do processo atual; em seguida, o **processo filho** geralmente chamava **`execve`** para carregar o novo executável e executá-lo. Depois, foi introduzido o **`vfork`** para tornar esse processo mais rápido, sem copiar memória.\
Então, foi introduzido o **`posix_spawn`**, que combina **`vfork`** e **`execve`** em uma única chamada e aceita flags:

- `POSIX_SPAWN_RESETIDS`: Redefine os IDs efetivos para os IDs reais
- `POSIX_SPAWN_SETPGROUP`: Define a associação ao grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Define o comportamento padrão dos sinais
- `POSIX_SPAWN_SETSIGMASK`: Define a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executa no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa o alocador Nano do libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` em segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fecha todas as descrições de arquivo por padrão em exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Aleatoriza os bits altos do deslocamento do ASLR

Além disso, `posix_spawn` aceita configurações **`posix_spawnattr`**, que controlam aspectos do processo criado, e entradas **`posix_spawn_file_actions`**, que modificam os descritores de arquivo.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai morreu, o novo pai é o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()`; até isso acontecer, o filho permanece em estado zumbi, ainda listado, mas sem consumir recursos.

### PIDs

PIDs, ou identificadores de processo, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonamente e **nunca dão a volta** (para evitar abusos).

### Grupos de processos, sessões e coalizões

Os **processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, os comandos em um script de shell estarão no mesmo grupo de processos, o que permite **enviar sinais a todos ao mesmo tempo** usando `kill`, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados nela, a menos que iniciem sua própria sessão.

Coalition é outra maneira de agrupar processos no Darwin. Um processo que entra em uma Coalition pode acessar recursos compartilhados, compartilhar um ledger ou ser afetado pelo Jetsam. As Coalitions têm diferentes funções: líder, serviço XPC e extensão.

### Credenciais e personae

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o ID de usuário e de grupo se o binário tiver o bit `setuid/setgid`.\
Há várias funções para **definir novos uids/gids**.

A chamada de sistema **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações a grupos **de uma só vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a estrutura:

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

1. **POSIX Threads (pthreads):** macOS oferece suporte a POSIX threads (`pthreads`), que fazem parte de uma API padrão de threads para C/C++. A implementação de pthreads no macOS está em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread`, disponível publicamente. Essa biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criação de Threads:** A função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, uma chamada de sistema de baixo nível específica do kernel XNU (o kernel no qual o macOS se baseia). Essa chamada de sistema recebe várias flags derivadas de `pthread_attr` (atributos), que especificam o comportamento da thread, incluindo políticas de escalonamento e tamanho da pilha.
   - **Tamanho Padrão da Pilha:** O tamanho padrão da pilha para novas threads é 512 KB, suficiente para operações típicas, mas pode ser ajustado por meio dos atributos da thread quando for necessário mais ou menos espaço.
3. **Inicialização de Threads:** A função `__pthread_init()` é essencial durante a configuração da thread. Ela usa o argumento `env[]` para analisar variáveis de ambiente, que podem incluir informações sobre a localização e o tamanho da pilha.

#### Encerramento de Threads no macOS

1. **Saída de Threads:** As threads normalmente são encerradas com uma chamada a `pthread_exit()`. Essa função permite que uma thread saia corretamente, realizando a limpeza necessária e permitindo que ela envie um valor de retorno a qualquer thread que aguarde sua conclusão.
2. **Limpeza de Threads:** Ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada para remover todas as estruturas associadas à thread. Ela desaloca as portas de threads Mach (Mach é o subsistema de comunicação no kernel XNU) e chama `bsdthread_terminate`, uma syscall que remove as estruturas do kernel associadas à thread.

#### Mecanismos de Sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS oferece vários mecanismos de sincronização. Eles são essenciais em ambientes multithread para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
   - **Mutex Regular (Assinatura: 0x4D555458):** Mutex padrão com uma pegada de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a assinatura).
   - **Mutex Rápido (Assinatura: 0x4d55545A):** Semelhante a um mutex regular, mas otimizado para operações mais rápidas; também tem 60 bytes.
2. **Variáveis de Condição:**
   - Usadas para aguardar a ocorrência de determinadas condições; têm 44 bytes (40 bytes mais uma assinatura de 4 bytes).
   - **Atributos de Variáveis de Condição (Assinatura: 0x434e4441):** Atributos de configuração para variáveis de condição, com 12 bytes.
3. **Variável Once (Assinatura: 0x4f4e4345):**
   - Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Read-Write Locks:**
   - Permitem vários leitores ou um escritor por vez, facilitando o acesso eficiente a dados compartilhados.
   - **Read Write Lock (Assinatura: 0x52574c4b):** Tem 196 bytes.
   - **Atributos de Read Write Lock (Assinatura: 0x52574c41):** Atributos para read-write locks, com 20 bytes.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar estouros.

### Variáveis Locais de Thread (TLV)

**Variáveis Locais de Thread (TLV)**, no contexto de arquivos Mach-O (o formato dos executáveis no macOS), são usadas para declarar variáveis específicas de **cada thread** em um aplicativo multithread. Isso garante que cada thread tenha sua própria instância separada de uma variável, oferecendo uma forma de evitar conflitos e manter a integridade dos dados sem precisar de mecanismos explícitos de sincronização, como mutexes.

Em C e linguagens relacionadas, é possível declarar uma variável local de thread usando a palavra-chave **`__thread`**. Veja como funciona no exemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este trecho define `tlv_var` como uma variável local à thread. Cada thread que executar este código terá sua própria `tlv_var`, e as alterações feitas por uma thread em `tlv_var` não afetarão a `tlv_var` de outra thread.

No binário Mach-O, os dados relacionados às variáveis locais à thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: Esta seção contém os metadados das variáveis locais à thread, como seus tipos e status de inicialização.
- **`__DATA.__thread_bss`**: Esta seção é usada para variáveis locais à thread que não são inicializadas explicitamente. Ela é uma região da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis locais à thread quando uma thread é encerrada. Essa API permite **registrar destrutores** — funções especiais que limpam os dados locais à thread quando ela termina.

### Prioridades de Thread

Para entender as prioridades de thread, é preciso analisar como o sistema operacional decide quais threads executar e quando. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas semelhantes ao Unix, isso é feito usando conceitos como `nice`, `renice` e classes de Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
   - O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo tem um valor `nice` entre -20 (prioridade mais alta) e 19 (prioridade mais baixa). O valor `nice` padrão ao criar um processo normalmente é 0.
   - Um valor `nice` menor (mais próximo de -20) torna um processo mais "egoísta", concedendo a ele mais tempo de CPU em comparação com outros processos que têm valores `nice` maiores.
2. **Renice:**
   - `renice` é um comando usado para alterar o valor `nice` de um processo em execução. Ele pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo o tempo de CPU alocado com base nos novos valores `nice`.
   - Por exemplo, se um processo precisar temporariamente de mais recursos de CPU, você pode reduzir seu valor `nice` usando `renice`.

#### Classes de Quality of Service (QoS)

As classes de QoS são uma abordagem mais moderna para gerenciar prioridades de thread, especialmente em sistemas como o macOS, que oferecem suporte ao **Grand Central Dispatch (GCD)**. As classes de QoS permitem que os desenvolvedores **categorize**m o trabalho em diferentes níveis, de acordo com sua importância ou urgência. O macOS gerencia automaticamente a priorização de threads com base nessas classes de QoS:

1. **User Interactive:**
   - Esta classe é destinada a tarefas que estão interagindo com o usuário no momento ou que precisam fornecer resultados imediatos para garantir uma boa experiência. Essas tarefas recebem a prioridade mais alta para manter a interface responsiva (por exemplo, animações ou tratamento de eventos).
2. **User Initiated:**
   - Tarefas iniciadas pelo usuário das quais se esperam resultados imediatos, como abrir um documento ou clicar em um botão que exige cálculos. Elas têm prioridade alta, mas inferior à de User Interactive.
3. **Utility:**
   - Essas tarefas são de longa duração e normalmente exibem um indicador de progresso (por exemplo, baixar arquivos ou importar dados). Têm prioridade inferior à das tarefas iniciadas pelo usuário e não precisam ser concluídas imediatamente.
4. **Background:**
   - Esta classe é destinada a tarefas executadas em segundo plano e que não são visíveis para o usuário. Podem ser tarefas como indexação, sincronização ou backups. Têm a menor prioridade e impacto mínimo no desempenho do sistema.

Com as classes de QoS, os desenvolvedores não precisam gerenciar os números exatos de prioridade; em vez disso, podem se concentrar na natureza da tarefa, enquanto o sistema otimiza os recursos de CPU de acordo.

Além disso, há diferentes **políticas de escalonamento de threads**, que permitem especificar um conjunto de parâmetros de escalonamento que o escalonador levará em conta. Isso pode ser feito com `thread_policy_[set/get]`. Esse recurso pode ser útil em ataques de race condition.

## Abuso de Processos no macOS

O macOS oferece muitos mecanismos para que **processos interajam, se comuniquem e compartilhem dados**. Embora esses mecanismos sejam essenciais para o funcionamento normal do sistema, atacantes podem abusar deles para fazer injection, executar código ou acessar dados.

### Library Injection

Library Injection é uma técnica na qual um atacante **força um processo a carregar uma library maliciosa**. Depois de injetada, a library é executada no contexto do processo-alvo, dando ao atacante as mesmas permissões e o mesmo acesso que o processo.

{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking envolve **interceptar chamadas de função** ou mensagens dentro do código de um software. Ao fazer hooking de funções, um atacante pode **modificar o comportamento** de um processo, observar dados confidenciais ou até mesmo controlar o fluxo de execução.

{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Esta página aborda metadados de unwind do ARM64, restrições do PAC no arm64e e cadeias de chamadas sintéticas.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) se refere a diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora o IPC seja fundamental para muitos aplicativos legítimos, também pode ser usado indevidamente para subverter o isolamento entre processos, vazar informações confidenciais ou executar ações não autorizadas.

{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplicativos Electron executados com variáveis de ambiente específicas podem estar vulneráveis a process injection:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **man in the browser attack**, que permite roubar teclas digitadas, tráfego e cookies, injetar scripts em páginas...

{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de um aplicativo. No entanto, eles podem **executar comandos arbitrários**, e o **Gatekeeper não impede** a execução de um aplicativo já executado se um **arquivo NIB for modificado**. Portanto, eles podem ser usados para fazer programas arbitrários executarem comandos arbitrários:

{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

É possível injetar opções da JVM por meio de **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`** e carregar um agente Java ou nativo antes de o aplicativo iniciar.

{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** pré-carrega JavaScript do atacante usando `--require` (arquivo) ou `--import data:text/javascript,…` (sem arquivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carrega um módulo em um REPL interativo, e **`ELECTRON_RUN_AS_NODE`** reativa tudo isso em binários Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

É possível injetar código em aplicativos .NET por meio de **`DOTNET_STARTUP_HOOKS`**, antes de `Main`, ou abusando da funcionalidade de depuração do .NET quando os pré-requisitos estão presentes.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

O Bash não interativo lê **`BASH_ENV`**; shells POSIX interativos leem **`ENV`**; o zsh lê **`$ZDOTDIR/.zshenv`**; e o fish lê configurações em **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Cada um pode executar um arquivo de inicialização controlado antes do comando pretendido. O Bash também executa uma substituição de comando colocada em **`PS4`** sempre que o xtrace está habilitado (por exemplo, por meio de **`SHELLOPTS=xtrace`** herdado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Iniciar `/bin/zsh -s` faz com que o shell leia um programa da entrada padrão. Portanto, um downloader que copia um documento estruturado não confiável para o stdin do processo filho sem analisá-lo primeiro transforma o documento inteiro em código-fonte de shell. Um loader observado transmitiu um arquivo iCalendar público por um pipe anônimo, linha por linha. Os metadados do calendário falharam como comandos, mas o zsh continuou até encontrar linhas executáveis inseridas após `DESCRIPTION:`. Essas linhas baixavam e iniciavam o próximo application bundle. O tipo de conteúdo esperado do arquivo e a hospedagem confiável não o tornavam seguro; o limite perigoso era passar seus bytes a um interpretador.<sup>[[5]](#references)</sup>

As etapas relacionadas são abordadas em [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper e quarantine](../macos-security-protections/macos-gatekeeper.md) e [locais de inicialização automática do macOS](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** podem carregar uma configuração PHP controlada cujo **`auto_prepend_file`** é executado antes do script-alvo.

[Injeção de inicialização por configuração do PHP e `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

O interpretador Lua independente executa código ou um `@file` de **`LUA_INIT`** (ou de sua variante específica da versão) antes de processar o script-alvo.

[Injeção de inicialização do Lua por `LUA_INIT` (arquivo e código inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** redirecionam os perfis de inicialização que contêm código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto com um caminho de library do R, podem ser usados para carregar automaticamente um pacote instalado.

[Perfis de inicialização e carregamento de pacotes do R](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** redireciona o depot cujo `config/startup.jl` é executado automaticamente.

[Injeção por `JULIA_DEPOT_PATH` e `startup.jl` do Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** podem injetar uma expressão Erlang VM **`-eval`** sem exigir um arquivo de payload; cargas de trabalho do Elixir normalmente iniciam a mesma VM.

[Injeção por flags da VM do Erlang/Elixir](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** redirecionam os scripts de inicialização do Octave.

[Injeção por arquivos de inicialização do GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` é um aplicativo .NET multiplataforma, portanto várias variáveis de ambiente permitem a execução antes do comando: **`XDG_CONFIG_HOME`** redireciona os scripts de perfil executados na inicialização, **`PSModulePath`** permite sequestrar o carregamento automático de módulos (um arquivo `.psm1` implantado é executado no momento da importação e pode se passar por cmdlets integrados), e as variáveis .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** carregam código do atacante no processo antes de `Main`.

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

[Opções de loader do Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

A cadeia da biblioteca padrão **`PYTHONWARNINGS`** e **`BROWSER`** pode executar um comando durante a análise dos filtros de avisos. Uma alternativa baseada em arquivo coloca `sitecustomize.py` em **`PYTHONPATH`**, para que a inicialização normal de `site` o importe antes do script-alvo. **`PYTHONBREAKPOINT`** executa uma função/módulo escolhido quando o código chega a `breakpoint()`. Variáveis exclusivas do modo interativo, como **`PYTHONSTARTUP`**, têm aplicabilidade mais limitada.

Observe que executáveis compilados com **`pyinstaller`** não usam essas variáveis de ambiente, mesmo quando são executados com um Python incorporado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (e seu fallback `EXINIT`) são executados como comandos Ex em uma inicialização normal; portanto, `:!cmd` / `:call system(...)` permitem a execução de código quando uma vítima abre o Vim/Neovim com um ambiente controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separadamente, o Homebrew costuma instalar o Python em `/opt/homebrew`, onde membros do grupo local `admin` podem conseguir substituir o launcher. Isso é um sequestro de binário gravável, não uma injeção por variável de ambiente; verifique a propriedade e as ACLs antes de considerá-lo explorável.

## Detecção

### Shield

[**Shield**](https://github.com/theevilbit/Shield) é um aplicativo de código aberto baseado em **EndpointSecurity** que detecta e bloqueia process injection. É uma boa referência para saber quais sinais são observáveis por meio do Endpoint Security, pois gera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variáveis de ambiente de injection** na execução de processos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chamadas a **`task_for_pid`** — um processo solicitando a porta de tarefa de outro, pré-requisito para injetar código nele.
- **Argumentos de depuração do Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, que iniciam um aplicativo Electron em modo de depuração e permitem que qualquer pessoa se conecte a ele e execute código.<sup>[[3]](#references)</sup>
- **Criação de symlinks/hardlinks entre níveis de privilégio** — a técnica clássica de "criar um link como usuário comum e apontá-lo para um local privilegiado". Observe que **symlinks podem gerar alertas, mas não ser bloqueados**: o EndpointSecurity não expõe o destino do link antes de sua criação.

### Chamadas feitas por outros processos

Neste [**artigo de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode descobrir como usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.<sup>[[4]](#references)</sup>

Observe que, para chamar essa função, é necessário ter o **mesmo uid** do processo em execução ou ser **root** (e ela retorna informações sobre o processo, não uma forma de injetar código).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — detecção de process injection no macOS de código aberto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por que aplicativos Electron não podem armazenar seus segredos confidencialmente: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detectando modificações de tarefas](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nova versão do stealer MacSync para macOS tem como alvo entusiastas de criptomoedas e desenvolvedores](https://securelist.com/macsync-new-version/121383/)
