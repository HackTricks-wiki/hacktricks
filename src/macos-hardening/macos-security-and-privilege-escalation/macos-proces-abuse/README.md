# Abuso de Processos no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas sobre Processos

Um processo é uma instância de um executável em execução; no entanto, os processos não executam código, e sim as threads. Portanto, **os processos são apenas contêineres para threads em execução**, fornecendo memória, descritores, portas, permissões...

Tradicionalmente, os processos eram iniciados dentro de outros processos (exceto o PID 1) chamando **`fork`**, que criaria uma cópia exata do processo atual; em seguida, o **processo filho** geralmente chamaria **`execve`** para carregar o novo executável e executá-lo. Depois, **`vfork`** foi introduzido para tornar esse processo mais rápido sem nenhuma cópia de memória.\
Em seguida, **`posix_spawn`** foi introduzido, combinando **`vfork`** e **`execve`** em uma única chamada e aceitando flags:

- `POSIX_SPAWN_RESETIDS`: Redefinir ids efetivos para ids reais
- `POSIX_SPAWN_SETPGROUP`: Definir a afiliação do grupo de processos
- `POSUX_SPAWN_SETSIGDEF`: Definir o comportamento padrão do sinal
- `POSIX_SPAWN_SETSIGMASK`: Definir a máscara de sinais
- `POSIX_SPAWN_SETEXEC`: Executar no mesmo processo (como `execve`, com mais opções)
- `POSIX_SPAWN_START_SUSPENDED`: Iniciar suspenso
- `_POSIX_SPAWN_DISABLE_ASLR`: Iniciar sem ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Usar o alocador Nano da libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Permitir `rwx` em segmentos de dados
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fechar todas as descrições de arquivo no exec(2) por padrão
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomizar os bits superiores do deslocamento do ASLR

Além disso, `posix_spawn` aceita configurações de **`posix_spawnattr`** que controlam aspectos do processo gerado e entradas de **`posix_spawn_file_actions`** que modificam descritores de arquivo.

Quando um processo morre, ele envia o **código de retorno ao processo pai** (se o pai tiver morrido, o novo pai será o PID 1) com o sinal `SIGCHLD`. O pai precisa obter esse valor chamando `wait4()` ou `waitid()`; até que isso aconteça, o filho permanece em um estado zumbi, no qual ainda é listado, mas não consome recursos.

### PIDs

PIDs, identificadores de processos, identificam um processo único. No XNU, os **PIDs** têm **64 bits**, aumentam monotonicamente e **nunca sofrem wraparound** (para evitar abusos).

### Grupos de Processos, Sessões e Coalitions

**Processos** podem ser inseridos em **grupos** para facilitar seu gerenciamento. Por exemplo, os comandos em um shell script estarão no mesmo grupo de processos, sendo possível **enviar sinais a todos eles em conjunto**, usando kill, por exemplo.\
Também é possível **agrupar processos em sessões**. Quando um processo inicia uma sessão (`setsid(2)`), os processos filhos são colocados dentro da sessão, a menos que iniciem sua própria sessão.

Coalition é outra forma de agrupar processos no Darwin. Um processo que ingressa em uma Coalition pode acessar recursos de pool, compartilhar um ledger ou ser submetido ao Jetsam. Coalitions têm diferentes funções: Leader, XPC service, Extension.

### Credenciais e Personae

Cada processo possui **credenciais** que **identificam seus privilégios** no sistema. Cada processo terá um `uid` primário e um `gid` primário (embora possa pertencer a vários grupos).\
Também é possível alterar o id de usuário e de grupo se o binário tiver o bit **`setuid/setgid`**.\
Existem várias funções para **definir novos uids/gids**.

O syscall **`persona`** fornece um conjunto **alternativo** de **credenciais**. Adotar uma persona assume seu uid, gid e associações de grupo **de uma só vez**. No [**código-fonte**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), é possível encontrar a struct:
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

1. **POSIX Threads (pthreads):** o macOS oferece suporte a POSIX threads (`pthreads`), que fazem parte de uma API padrão de threading para C/C++. A implementação de pthreads no macOS está em `/usr/lib/system/libsystem_pthread.dylib`, proveniente do projeto `libpthread`, disponível publicamente. Essa biblioteca fornece as funções necessárias para criar e gerenciar threads.
2. **Criação de Threads:** a função `pthread_create()` é usada para criar novas threads. Internamente, essa função chama `bsdthread_create()`, que é uma chamada de sistema de nível inferior específica do kernel XNU (o kernel no qual o macOS se baseia). Essa chamada de sistema recebe várias flags derivadas de `pthread_attr` (atributos) que especificam o comportamento da thread, incluindo políticas de escalonamento e o tamanho da stack.
- **Tamanho padrão da stack:** o tamanho padrão da stack para novas threads é de 512 KB, o que é suficiente para operações típicas, mas pode ser ajustado por meio dos atributos da thread caso seja necessário mais ou menos espaço.
3. **Inicialização da Thread:** a função `__pthread_init()` é fundamental durante a configuração da thread, utilizando o argumento `env[]` para analisar variáveis de ambiente que podem incluir detalhes sobre a localização e o tamanho da stack.

#### Encerramento de Threads no macOS

1. **Saída de Threads:** as threads geralmente são encerradas chamando `pthread_exit()`. Essa função permite que uma thread saia de forma limpa, realizando a limpeza necessária e permitindo que ela envie um valor de retorno para qualquer thread que esteja aguardando sua conclusão.
2. **Limpeza da Thread:** ao chamar `pthread_exit()`, a função `pthread_terminate()` é invocada. Ela lida com a remoção de todas as estruturas associadas à thread. A função desaloca as portas de thread do Mach (Mach é o subsistema de comunicação do kernel XNU) e chama `bsdthread_terminate`, um syscall que remove as estruturas no nível do kernel associadas à thread.

#### Mecanismos de Sincronização

Para gerenciar o acesso a recursos compartilhados e evitar race conditions, o macOS fornece várias primitivas de sincronização. Elas são essenciais em ambientes multithreading para garantir a integridade dos dados e a estabilidade do sistema:

1. **Mutexes:**
- **Mutex regular (Signature: 0x4D555458):** mutex padrão com um footprint de memória de 60 bytes (56 bytes para o mutex e 4 bytes para a signature).
- **Fast Mutex (Signature: 0x4d55545A):** semelhante a um mutex regular, mas otimizado para operações mais rápidas, também com 60 bytes de tamanho.
2. **Condition Variables:**
- Usadas para aguardar a ocorrência de determinadas condições, com um tamanho de 44 bytes (40 bytes mais uma signature de 4 bytes).
- **Atributos de Condition Variable (Signature: 0x434e4441):** atributos de configuração para condition variables, com tamanho de 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
- Garante que um trecho de código de inicialização seja executado apenas uma vez. Seu tamanho é de 12 bytes.
4. **Read-Write Locks:**
- Permitem vários leitores ou um escritor por vez, facilitando o acesso eficiente a dados compartilhados.
- **Read Write Lock (Signature: 0x52574c4b):** com tamanho de 196 bytes.
- **Atributos de Read Write Lock (Signature: 0x52574c41):** atributos para read-write locks, com tamanho de 20 bytes.

> [!TIP]
> Os últimos 4 bytes desses objetos são usados para detectar overflows.

### Thread Local Variables (TLV)

As **Thread Local Variables (TLV)** no contexto de arquivos Mach-O (o formato dos executáveis no macOS) são usadas para declarar variáveis específicas de **cada thread** em uma aplicação multithread. Isso garante que cada thread tenha sua própria instância separada de uma variável, fornecendo uma forma de evitar conflitos e manter a integridade dos dados sem precisar de mecanismos explícitos de sincronização, como mutexes.

Em C e linguagens relacionadas, você pode declarar uma variável thread-local usando a palavra-chave **`__thread`**. Veja como isso funciona no seu exemplo:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Este snippet define `tlv_var` como uma variável thread-local. Cada thread que executa este código terá sua própria `tlv_var`, e as alterações feitas por uma thread em `tlv_var` não afetarão a `tlv_var` de outra thread.

No binário Mach-O, os dados relacionados às variáveis thread-local são organizados em seções específicas:

- **`__DATA.__thread_vars`**: Esta seção contém os metadados sobre as variáveis thread-local, como seus tipos e status de inicialização.
- **`__DATA.__thread_bss`**: Esta seção é usada para variáveis thread-local que não são inicializadas explicitamente. Ela faz parte da memória reservada para dados inicializados com zero.

O Mach-O também fornece uma API específica chamada **`tlv_atexit`** para gerenciar variáveis thread-local quando uma thread termina. Essa API permite **registrar destrutores** — funções especiais que limpam os dados thread-local quando uma thread é encerrada.

### Threading Priorities

Entender as prioridades de threads envolve analisar como o sistema operacional decide quais threads executar e quando executá-las. Essa decisão é influenciada pelo nível de prioridade atribuído a cada thread. No macOS e em sistemas semelhantes ao Unix, isso é tratado usando conceitos como `nice`, `renice` e classes Quality of Service (QoS).

#### Nice e Renice

1. **Nice:**
- O valor `nice` de um processo é um número que afeta sua prioridade. Todo processo tem um valor nice entre -20 (a prioridade mais alta) e 19 (a prioridade mais baixa). O valor nice padrão quando um processo é criado normalmente é 0.
- Um valor nice menor (mais próximo de -20) torna um processo mais "egoísta", concedendo-lhe mais tempo de CPU em comparação com outros processos que têm valores nice mais altos.
2. **Renice:**
- `renice` é um comando usado para alterar o valor nice de um processo já em execução. Isso pode ser usado para ajustar dinamicamente a prioridade dos processos, aumentando ou diminuindo sua alocação de tempo de CPU com base nos novos valores nice.
- Por exemplo, se um processo precisar temporariamente de mais recursos de CPU, você poderá diminuir seu valor nice usando `renice`.

#### Quality of Service (QoS) Classes

As classes QoS são uma abordagem mais moderna para lidar com prioridades de threads, especialmente em sistemas como o macOS que oferecem suporte ao **Grand Central Dispatch (GCD)**. As classes QoS permitem que os desenvolvedores **categorize**m o trabalho em diferentes níveis com base em sua importância ou urgência. O macOS gerencia automaticamente a priorização das threads com base nessas classes QoS:

1. **User Interactive:**
- Esta classe é destinada a tarefas que estão interagindo com o usuário ou que exigem resultados imediatos para proporcionar uma boa experiência. Essas tarefas recebem a prioridade mais alta para manter a interface responsiva (por exemplo, animações ou manipulação de eventos).
2. **User Initiated:**
- Tarefas iniciadas pelo usuário que exigem resultados imediatos, como abrir um documento ou clicar em um botão que requer processamento. Elas têm alta prioridade, mas ficam abaixo de User Interactive.
3. **Utility:**
- Essas tarefas são de longa duração e normalmente exibem um indicador de progresso (por exemplo, baixar arquivos ou importar dados). Elas têm prioridade menor que as tarefas iniciadas pelo usuário e não precisam ser concluídas imediatamente.
4. **Background:**
- Esta classe é destinada a tarefas executadas em segundo plano e que não são visíveis para o usuário. Elas podem incluir tarefas como indexação, sincronização ou backups. Têm a menor prioridade e impacto mínimo no desempenho do sistema.

Usando classes QoS, os desenvolvedores não precisam gerenciar números exatos de prioridade, mas apenas se concentrar na natureza da tarefa; o sistema otimiza os recursos de CPU de acordo com isso.

Além disso, existem diferentes **thread scheduling policies** que permitem especificar um conjunto de parâmetros de agendamento que o scheduler levará em consideração. Isso pode ser feito usando `thread_policy_[set/get]`. Isso pode ser útil em ataques de race condition.

## macOS Process Abuse

O macOS fornece muitos mecanismos para que **processos interajam, se comuniquem e compartilhem dados**. Embora esses mecanismos sejam essenciais para a operação normal do sistema, attackers podem abusar deles para injection, code execution ou acesso a dados.

### Library Injection

Library Injection é uma técnica na qual um attacker **força um processo a carregar uma library maliciosa**. Depois de injetada, a library é executada no contexto do processo-alvo, fornecendo ao attacker as mesmas permissões e o mesmo acesso que o processo possui.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking envolve **interceptar chamadas de funções** ou mensagens dentro do código de um software. Ao fazer hooking de funções, um attacker pode **modificar o comportamento** de um processo, observar dados sensíveis ou até mesmo obter controle sobre o fluxo de execução.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) refere-se aos diferentes métodos pelos quais processos separados **compartilham e trocam dados**. Embora IPC seja fundamental para muitas aplicações legítimas, também pode ser usado indevidamente para subverter o isolamento de processos, causar leak de informações sensíveis ou executar ações não autorizadas.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Aplicações Electron executadas com variáveis de ambiente específicas podem ser vulneráveis a process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

É possível usar as flags `--load-extension` e `--use-fake-ui-for-media-stream` para realizar um **man in the browser attack**, permitindo roubar keystrokes, tráfego e cookies, além de injetar scripts nas páginas...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Arquivos NIB **definem elementos da interface do usuário (UI)** e suas interações dentro de uma aplicação. No entanto, eles podem **executar comandos arbitrários**, e o **Gatekeeper não impede** que uma aplicação já executada seja executada novamente caso um **arquivo NIB seja modificado**. Portanto, eles podem ser usados para fazer com que programas arbitrários executem comandos arbitrários:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

É possível injetar opções da JVM por meio de **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`** e carregar um agent Java ou nativo antes que a aplicação seja iniciada.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

É possível injetar código em aplicações .NET por meio de **`DOTNET_STARTUP_HOOKS`** antes de `Main`, ou abusando da funcionalidade de debugging do .NET quando seus pré-requisitos estão presentes.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

O Bash não interativo lê **`BASH_ENV`**; o zsh lê **`$ZDOTDIR/.zshenv`**; e o fish lê configurações abaixo de **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Cada um pode executar um arquivo de inicialização controlado antes do comando pretendido:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** podem carregar uma configuração PHP controlada cujo **`auto_prepend_file`** é executado antes do script-alvo.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

O interpretador Lua standalone executa código ou um `@file` definido em **`LUA_INIT`** (ou em sua variante específica de versão) antes de processar o script-alvo.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** e **`R_PROFILE`** redirecionam perfis de inicialização que contêm código R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, juntamente com um caminho para uma library R, podem, alternativamente, carregar automaticamente um package instalado.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redireciona o depot cujo `config/startup.jl` é executado automaticamente.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** podem injetar uma expressão Erlang **`-eval`** na VM sem exigir um arquivo de payload; workloads Elixir normalmente iniciam a mesma VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** e **`OCTAVE_VERSION_INITFILE`** redirecionam os scripts de inicialização do Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

No macOS e no Linux, **`XDG_CONFIG_HOME`** pode redirecionar os perfis de usuário do PowerShell que são executados quando o `pwsh` é iniciado.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Verifique diferentes opções para fazer um script Perl executar código arbitrário em:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Também é possível abusar das variáveis de ambiente do Ruby para fazer com que scripts arbitrários executem código arbitrário:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

A cadeia da standard library formada por **`PYTHONWARNINGS`** e **`BROWSER`** pode executar um comando durante a análise do filtro de avisos. Uma alternativa baseada em arquivo coloca `sitecustomize.py` em **`PYTHONPATH`**, fazendo com que a inicialização normal de `site` importe esse arquivo antes do script-alvo. Variáveis exclusivas do modo interativo, como **`PYTHONSTARTUP`**, têm aplicabilidade mais restrita.

Observe que executáveis compilados com **`pyinstaller`** não usam essas variáveis de ambiente, mesmo quando são executados usando um Python incorporado.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Separadamente, o Homebrew normalmente instala o Python abaixo de `/opt/homebrew`, onde membros do grupo local `admin` podem conseguir substituir o launcher. Isso é um hijack de binário gravável, e não uma injection de variável de ambiente; verifique ownership e ACLs antes de considerá-lo explorável.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) é uma aplicação open source baseada em **EndpointSecurity** que detecta e bloqueia process injection. Ela é uma boa referência para identificar quais sinais podem ser observados por meio do Endpoint Security, pois gera alertas sobre:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variáveis de ambiente de injection** durante o exec de processos: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` e `ELECTRON_RUN_AS_NODE`.
- Chamadas **`task_for_pid`** — um processo solicitando a task port de outro, o que é um pré-requisito para injetar código nele.
- **Argumentos de debugging do Electron** — `--inspect`, `--inspect-brk` e `--remote-debugging-port`, que iniciam uma aplicação Electron em modo de debugging e permitem que qualquer pessoa se conecte a ela e execute código.<sup>[[3]](#references)</sup>
- **Criação de symlinks/hardlinks entre níveis de privilégio** — a primitiva clássica de "criar um link como usuário normal e apontá-lo para um local privilegiado". Observe que **symlinks podem gerar alertas, mas não podem ser bloqueados**: o EndpointSecurity não expõe o destino do link antes de sua criação.

### Calls made by other processes

Nesta [**publicação de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode encontrar informações sobre como usar a função **`task_name_for_pid`** para obter informações sobre outros **processos que injetam código em um processo** e, em seguida, obter informações sobre esse outro processo.<sup>[[4]](#references)</sup>

Observe que, para chamar essa função, é necessário ter **o mesmo uid** que executa o processo ou ser **root** (e ela retorna informações sobre o processo, não uma forma de injetar código).

## References

- [1] [Shield — detecção open source de process injection no macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Por que aplicações Electron não conseguem armazenar seus segredos de forma confidencial: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detectando modificações de tasks](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
