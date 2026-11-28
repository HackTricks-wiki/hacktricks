# Abuso de Processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas sobre Processos

Um processo é uma instância de um executável em execução. No entanto, os processos não executam código; quem o faz são as threads. Portanto, **os processos são apenas contêineres para threads em execução**, fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criava uma cópia exata do processo atual. Em seguida, o **processo filho** geralmente chamava **`execve`** para carregar o novo executável e executá-lo. Depois, foi introduzido **`vfork`** para tornar esse processo mais rápido, sem copiar a memória.\
Em seguida, foi introduzido **`posix_spawn`**, que combina **`vfork`** e **`execve`** em uma única chamada e aceita flags:

- `POSIX_SPAWN_RESETIDS`: Redefine os IDs efetivos para os IDs reais
- `POSIX_SPAWN_SETPGROUP`: Define a afiliação ao grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Define o comportamento padrão dos sinais
- `POSIX_SPAWN_SETSIGMASK`: Define a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executa no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Inicia suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Inicia sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usa o alocador Nano do libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permite `rwx` nos segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fecha todas as descrições de arquivos por padrão ao executar exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiza os bits superiores do deslocamento do ASLR

Além disso, `posix_spawn` aceita configurações **`posix_spawnattr`**, que controlam aspectos do processo iniciado, e entradas **`posix_spawn_file_actions`**, que modificam os descritores de arquivos.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai morreu, o novo pai é o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()`; até que isso aconteça, o filho permanece em estado zumbi, no qual ainda aparece na lista, mas não consome recursos.

### PIDs

PIDs, ou identificadores de processos, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonicamente e **nunca dão a volta** (para evitar abusos).

### Grupos de Processos, Sessões e Coalizões

**Os processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, os comandos em um script de shell estarão no mesmo grupo de processos, de modo que seja possível **enviar sinais a todos de uma vez**, usando `kill`, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são inseridos nela, a menos que iniciem sua própria sessão.

Coalizão é outra forma de agrupar processos no Darwin. Um processo que entra em uma coalizão pode acessar recursos do pool, compartilhar um ledger ou ser afetado pelo Jetsam. As coalizões têm diferentes funções: líder, serviço XPC e extensão.

### Credenciais e Personae

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` e um `gid` primários (embora possa pertencer a vários grupos).\
Também é possível alterar o ID de usuário e de grupo se o binário tiver o bit `setuid/setgid`.\
Há várias funções para **definir novos uids/gids**.

A chamada de sistema **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume de uma só vez seu uid, gid e associações a grupos. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a struct:

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

1. **POSIX Threads (pthreads):** o macOS oferece suporte a POSIX threads (`pthreads`), que fazem parte de uma API padrão de threading para C/C++. A implementação de pthreads no macOS está em `/usr/lib/system/libsystem_pthread.dylib`, que vem do projeto `libpthread`, disponível publicamente. Essa biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criação de threads:** a função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, uma chamada de sistema de nível mais baixo específica do kernel XNU (o kernel no qual o macOS se baseia). Essa chamada de sistema recebe vários flags derivados de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de agendamento e tamanho da stack.
   - **Tamanho padrão da stack:** o tamanho padrão da stack para novas threads é 512 KB, suficiente para operações típicas, mas pode ser ajustado por meio dos atributos da thread caso seja necessário mais ou menos espaço.
3. **Inicialização de threads:** a função `__pthread_init()` é essencial durante a configuração de uma thread e usa o argumento `env[]` para analisar variáveis de ambiente que podem incluir detalhes sobre a localização e o tamanho da stack.

#### Encerramento de threads no macOS

1. **Saída de threads:** normalmente, as threads são encerradas chamando `pthread_exit()`. Essa função permite que uma thread saia de forma limpa, execute a limpeza necessária e envie um valor de retorno a qualquer thread que aguarde seu término.
2. **Limpeza de threads:** ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada para remover todas as estruturas associadas à thread. Ela desaloca as portas de thread Mach (Mach é o subsistema de comunicação no kernel XNU) e chama `bsdthread_terminate`, uma syscall que remove as estruturas no nível do kernel associadas à thread.

#### Mecanismos de sincronização

Para gerenciar o acesso a recursos compartilhados e evitar condições de corrida, o macOS oferece várias primitivas de sincronização. Elas são essenciais em ambientes multithread para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
   - **Mutex regular (assinatura: 0x4D555458):** mutex padrão com uma ocupação de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a assinatura).
   - **Mutex rápido (assinatura: 0x4d55545A):** semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes.
2. **Variáveis de condição:**
   - Usadas para aguardar a ocorrência de determinadas condições, com 44 bytes (40 bytes mais uma assinatura de 4 bytes).
   - **Atributos de variável de condição (assinatura: 0x434e4441):** atributos de configuração para variáveis de condição, com 12 bytes.
3. **Variável Once (assinatura: 0x4f4e4345):**
   - Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Locks de leitura e escrita:**
   - Permitem vários leitores ou um escritor por vez, facilitando o acesso eficiente aos dados compartilhados.
   - **Lock de leitura e escrita (assinatura: 0x52574c4b):** tem 196 bytes.
   - **Atributos de lock de leitura e escrita (assinatura: 0x52574c41):** atributos para locks de leitura e escrita, com 20 bytes.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar estouros.

### Variáveis locais a threads (TLV)

**Variáveis locais a threads (TLV)**, no contexto de arquivos Mach-O (o formato dos executáveis no macOS), são usadas para declarar variáveis específicas de **cada thread** em um aplicativo multithread. Isso garante que cada thread tenha sua própria instância separada de uma variável, oferecendo uma forma de evitar conflitos e manter a integridade dos dados sem precisar de mecanismos de sincronização explícitos, como mutexes.

Em C e linguagens relacionadas, é possível declarar uma variável local a uma thread usando a palavra-chave **`__thread`**. Veja como isso funciona no exemplo:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Este trecho define `tlv_var` como uma variável local à thread. Cada thread que executa este código terá sua própria `tlv_var`, e as alterações que uma thread fizer em `tlv_var` não afetarão a `tlv_var` de outra thread.

No binário Mach-O, os dados relacionados às variáveis locais à thread são organizados em seções específicas:

- **`__DATA.__thread_vars`**: esta seção contém os metadados das variáveis locais à thread, como seus tipos e o status de inicialização.
- **`__DATA.__thread_bss`**: esta seção é usada para variáveis locais à thread que não são inicializadas explicitamente. É uma região da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis locais à thread quando uma thread termina. Essa API permite **registrar destrutores** — funções especiais que limpam os dados locais à thread quando uma thread termina.

### Prioridades de threads

Para entender as prioridades de threads, é preciso analisar como o sistema operacional decide quais threads executar e quando. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas semelhantes ao Unix, isso é tratado com conceitos como `nice`, `renice` e classes Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
   - O valor `nice` de um processo é um número que afeta sua prioridade. Cada processo tem um valor `nice` entre -20 (prioridade mais alta) e 19 (prioridade mais baixa). O valor `nice` padrão quando um processo é criado normalmente é 0.
   - Um valor `nice` mais baixo (mais próximo de -20) torna um processo mais “egoísta”, concedendo a ele mais tempo de CPU em comparação com outros processos com valores `nice` mais altos.
2. **Renice:**
   - `renice` é um comando usado para alterar o valor `nice` de um processo já em execução. Ele pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo o tempo de CPU alocado com base nos novos valores `nice`.
   - Por exemplo, se um processo precisar temporariamente de mais recursos de CPU, você pode reduzir seu valor `nice` usando `renice`.

#### Classes Quality of Service (QoS)

As classes QoS são uma abordagem mais moderna para lidar com prioridades de threads, especialmente em sistemas como o macOS, que oferecem suporte a **Grand Central Dispatch (GCD)**. As classes QoS permitem que os desenvolvedores **categorizar** o trabalho em diferentes níveis, conforme sua importância ou urgência. O macOS gerencia automaticamente a priorização das threads com base nessas classes QoS:

1. **User Interactive:**
   - Esta classe é destinada a tarefas que estão interagindo com o usuário no momento ou que precisam fornecer resultados imediatos para garantir uma boa experiência. Essas tarefas recebem a prioridade mais alta para manter a interface responsiva (por exemplo, animações ou tratamento de eventos).
2. **User Initiated:**
   - Tarefas iniciadas pelo usuário das quais se esperam resultados imediatos, como abrir um documento ou clicar em um botão que exige cálculos. Elas têm prioridade alta, mas inferior à de User Interactive.
3. **Utility:**
   - Essas tarefas são de longa duração e normalmente exibem um indicador de progresso (por exemplo, baixar arquivos ou importar dados). Sua prioridade é inferior à das tarefas iniciadas pelo usuário e não precisam terminar imediatamente.
4. **Background:**
   - Esta classe é destinada a tarefas executadas em segundo plano e que não ficam visíveis para o usuário. Podem ser tarefas como indexação, sincronização ou backups. Elas têm a prioridade mais baixa e impacto mínimo no desempenho do sistema.

Com as classes QoS, os desenvolvedores não precisam gerenciar os valores exatos de prioridade; podem se concentrar na natureza da tarefa, enquanto o sistema otimiza os recursos de CPU de acordo.

Além disso, há diferentes **políticas de escalonamento de threads** que permitem especificar um conjunto de parâmetros de escalonamento que o scheduler levará em consideração. Isso pode ser feito usando `thread_policy_[set/get]`. Esse recurso pode ser útil em ataques de race condition.

## Abuso de processos no macOS

O macOS oferece muitos mecanismos para que **processos interajam, se comuniquem e compartilhem dados**. Embora esses mecanismos sejam essenciais para o funcionamento normal do sistema, atacantes podem abusar deles para fazer injection, executar código ou acessar dados.

### Library Injection

Library Injection é uma técnica na qual um atacante **força um processo a carregar uma biblioteca maliciosa**. Depois de injetada, a biblioteca é executada no contexto do processo-alvo, concedendo ao atacante as mesmas permissões e o mesmo acesso do processo.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking envolve **interceptar chamadas de função** ou mensagens em um código de software. Ao fazer hooking de funções, um atacante pode **modificar o comportamento** de um processo, observar dados sensíveis ou até assumir o controle do fluxo de execução.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Esta página aborda metadados de unwind do ARM64, restrições PAC do arm64e e cadeias de chamadas sintéticas.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) refere-se a diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora o IPC seja fundamental para muitos aplicativos legítimos, também pode ser usado indevidamente para subverter o isolamento entre processos, vazar informações sensíveis ou realizar ações não autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplicativos Electron executados com variáveis de ambiente específicas podem estar vulneráveis a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **ataque man in the browser**, que permite roubar teclas digitadas, tráfego e cookies, injetar scripts em páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de um aplicativo. No entanto, eles podem **executar comandos arbitrários**, e o **Gatekeeper não impede** que um aplicativo já executado seja executado novamente se um **arquivo NIB for modificado**. Portanto, eles podem ser usados para fazer programas arbitrários executarem comandos arbitrários:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

É possível injetar opções da JVM por meio de **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`** e carregar um agente Java ou nativo antes do início do aplicativo.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** pré-carrega JavaScript controlado pelo atacante via `--require` (arquivo) ou `--import data:text/javascript,…` (sem arquivo, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** carrega um módulo em um REPL interativo, e **`ELECTRON_RUN_AS_NODE`** reabilita tudo isso em binários Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

É possível injetar código em aplicativos .NET por meio de **`DOTNET_STARTUP_HOOKS`**, antes de `Main`, ou abusando da funcionalidade de depuração do .NET quando seus pré-requisitos estão presentes.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

O Bash não interativo lê **`BASH_ENV`**; shells POSIX interativos leem **`ENV`**; o zsh lê **`$ZDOTDIR/.zshenv`**; e o fish lê configurações em **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Cada um pode executar um arquivo de inicialização controlado antes do comando pretendido. O Bash também executa uma substituição de comando inserida em **`PS4`** sempre que o xtrace está habilitado (por exemplo, com **`SHELLOPTS=xtrace`** herdado):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Contrabando de comandos via stdin do shell

Ao iniciar `/bin/zsh -s`, o shell lê um programa da entrada padrão. Portanto, um downloader que copia um documento estruturado não confiável para o stdin do processo filho sem analisá-lo primeiro transforma o documento inteiro em código-fonte do shell. Um loader observado transmitia um arquivo iCalendar público por um pipe anônimo, linha por linha. Os metadados do calendário falhavam como comandos, mas o zsh continuava até encontrar linhas executáveis colocadas após `DESCRIPTION:`. Essas linhas baixavam e iniciavam o próximo bundle de aplicativo. O tipo de conteúdo esperado do arquivo e a hospedagem confiável não o tornavam seguro; o limite perigoso era passar seus bytes para um interpretador.<sup>[[5]](#references)</sup>

Etapas relacionadas são abordadas em [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) e [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** podem carregar uma configuração PHP controlada cujo **`auto_prepend_file`** é executado antes do script-alvo.

[Injeção na inicialização via configuração PHP e `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

O interpretador Lua independente executa código ou um `@file` de **`LUA_INIT`** (ou de sua variante específica da versão) antes de processar o script-alvo.

[Injeção na inicialização via `LUA_INIT` do Lua (arquivo e código inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** redirecionam para perfis de inicialização que contêm código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, junto com um caminho de biblioteca R, podem carregar automaticamente um pacote instalado.

[Perfis de inicialização do R e carregamento de pacotes](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** redireciona para o depot cujo `config/startup.jl` é executado automaticamente.

[Injeção via `JULIA_DEPOT_PATH` e `startup.jl` do Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** podem injetar uma expressão Erlang VM **`-eval`** sem exigir um arquivo de payload; cargas de trabalho Elixir normalmente iniciam a mesma VM.

[Injeção via flags da VM Erlang/Elixir](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** redirecionam para scripts de inicialização do Octave.

[Injeção por arquivos de inicialização do GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` é um aplicativo .NET multiplataforma, portanto, diversas variáveis de ambiente permitem a execução antes do comando: **`XDG_CONFIG_HOME`** redireciona os scripts de perfil executados na inicialização, **`PSModulePath`** sequestra o carregamento automático de módulos (um arquivo `.psm1` inserido é executado no momento da importação e pode ocultar cmdlets integrados), e as variáveis .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** e **`DOTNET_STARTUP_HOOKS`** carregam código do atacante no processo antes de `Main`.

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


[Opções do loader Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

A cadeia da biblioteca padrão **`PYTHONWARNINGS`** e **`BROWSER`** pode executar um comando durante a análise dos filtros de aviso. Uma alternativa baseada em arquivo coloca `sitecustomize.py` em **`PYTHONPATH`**, para que a inicialização normal de `site` o importe antes do script-alvo. **`PYTHONBREAKPOINT`** executa um callable/módulo escolhido quando o código chega a `breakpoint()`.

No CPython 3.13+, **`PYTHONINSPECT`** também pode executar um arquivo **`PYTHONSTARTUP`** após um script quando o PyREPL é iniciado em um terminal.<sup>[[6]](#references)</sup>

Observe que executáveis compilados com **`pyinstaller`** não usam essas variáveis de ambiente, mesmo quando executados com um Python incorporado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (e sua alternativa `EXINIT`) são executadas como comandos Ex durante a inicialização normal, portanto, `:!cmd` / `:call system(...)` permitem execução de código quando uma vítima abre o Vim/Neovim com um ambiente controlado:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Separadamente, o Homebrew costuma instalar o Python em `/opt/homebrew`, onde membros do grupo local `admin` podem conseguir substituir o launcher. Isso é um sequestro de binário gravável, não uma injection por variável de ambiente; verifique a propriedade e as ACLs antes de considerá-lo explorável.


## Detecção

### Shield

[**Shield**](https://github.com/theevilbit/Shield) é um aplicativo de código aberto baseado em **EndpointSecurity** que detecta e bloqueia process injection. É uma boa referência dos sinais observáveis por meio do Endpoint Security, pois gera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variáveis de ambiente de injection** na execução de processos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chamadas **`task_for_pid`** — um processo solicitando a task port de outro processo, pré-requisito para injetar código nele.
- **Argumentos de depuração do Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, que iniciam um aplicativo Electron em modo de depuração e permitem que qualquer pessoa se conecte a ele e execute código.<sup>[[3]](#references)</sup>
- **Criação de symlink/hardlink entre níveis de privilégio** — a técnica clássica de “criar um link como usuário comum e apontá-lo para um local privilegiado”. Observe que **symlinks podem gerar alertas, mas não podem ser bloqueados**: o EndpointSecurity não expõe o destino do link antes de sua criação.

### Chamadas feitas por outros processos

Neste [**artigo de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode descobrir como usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.<sup>[[4]](#references)</sup>

Observe que, para chamar essa função, você precisa ter **o mesmo uid** que o processo em execução ou ser **root** (e ela retorna informações sobre o processo, não uma forma de injetar código).



## References

- [1] [Shield — detecção de process injection no macOS de código aberto (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por que aplicativos Electron não podem armazenar seus segredos de forma confidencial: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detectando modificações de tasks](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Nova versão do stealer MacSync para macOS tem como alvo entusiastas de criptomoedas e desenvolvedores](https://securelist.com/macsync-new-version/121383/)
- [6] [Linha de comando e ambiente do Python — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
