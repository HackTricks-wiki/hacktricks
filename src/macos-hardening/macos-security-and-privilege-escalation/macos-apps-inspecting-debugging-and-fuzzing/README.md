# Apps do macOS - Inspeção, depuração e Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Análise estática

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (antigo jtool2)

Você pode [**baixar o disarm aqui**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Observe que **`disarm`** também pode funcionar com arquivos IM4P compactados (como `kernelcache`) e extrair apenas as partes necessárias ou até analisar a parte necessária sem extraí-la.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** pode ser encontrado no **macOS**, enquanto **`ldid`** pode ser encontrado no **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que há dentro antes de instalá-los.\
Esses instaladores têm scripts bash `preinstall` e `postinstall` que autores de malware costumam usar para garantir a **persistência** do **malware**.

### hdiutil

Esta ferramenta **monta** arquivos de imagem de disco da Apple (`.dmg`) para que possam ser inspecionados antes de qualquer coisa ser executada:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Ele será montado em `/Volumes`

### Binaries compactados

- Verifique se há alta entropia
- Verifique as strings (se quase não houver strings compreensíveis, o binário está compactado)
- O packer UPX para macOS gera uma seção chamada `__XHDR`.

## Análise estática de Objective-C

### Metadados

> [!CAUTION]
> Observe que programas escritos em Objective-C **retêm** suas declarações de classes **quando são** **compilados** em [binaries Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Essas declarações de classes **incluem** o nome e o tipo de:

- As interfaces definidas
- Os métodos das interfaces
- As variáveis de instância das interfaces
- Os protocolos definidos

Observe que esses nomes podem ser ofuscados para dificultar a engenharia reversa do binário.

### Chamada de funções

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chama **`objc_msgSend`**, que chamará a função final:

![Metadados - Chamada de funções: Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará objc msgSend. Que chamará...](<../../../images/image (305).png>)

Os parâmetros esperados por essa função são:

- O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que deve receber a mensagem**". Ou, de forma mais simples, é o objeto sobre o qual o método está sendo invocado. Se o método for um método de classe, será uma instância do objeto da classe (como um todo); já para um método de instância, self apontará para uma instância da classe criada como um objeto.
- O segundo parâmetro (**op**) é "o seletor do método que trata a mensagem". Ou, de forma mais simples, é apenas o **nome do método**.
- Os parâmetros restantes são quaisquer **valores exigidos pelo método** (op).

Veja como **obter facilmente essas informações com `lldb` em ARM64** nesta página:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**      | **Registrador**                                                | **(para) objc_msgSend**                                  |
| ------------------ | -------------------------------------------------------------- | -------------------------------------------------------- |
| **1º argumento**   | **rdi**                                                        | **self: objeto sobre o qual o método está sendo invocado** |
| **2º argumento**   | **rsi**                                                        | **op: nome do método**                                   |
| **3º argumento**   | **rdx**                                                        | **1º argumento do método**                               |
| **4º argumento**   | **rcx**                                                        | **2º argumento do método**                               |
| **5º argumento**   | **r8**                                                         | **3º argumento do método**                               |
| **6º argumento**   | **r9**                                                         | **4º argumento do método**                               |
| **7º argumento em diante** | <p><strong>rsp+</strong><br><strong>(na stack)</strong></p> | **5º argumento do método em diante**                     |

### Despejar metadados de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) é uma ferramenta para fazer class-dump de binários Objective-C. O GitHub especifica dylibs, mas a ferramenta também funciona com executáveis.

```bash
./dynadump dump /path/to/bin
```

No momento da redação, esta é **a que funciona melhor atualmente**.

#### Ferramentas convencionais

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) é a ferramenta original para gerar declarações das classes, categorias e protocolos em código formatado de ObjetiveC.

É antiga e não é mantida, então provavelmente não funcionará corretamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) é uma ferramenta moderna e multiplataforma para fazer dump de classes Objective-C. Em comparação com as ferramentas existentes, iCDump pode ser executada independentemente do ecossistema Apple e oferece bindings para Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Análise estática de Swift

Com binários Swift, devido à compatibilidade com Objective-C, às vezes é possível extrair declarações usando [class-dump](https://github.com/nygard/class-dump/), mas nem sempre.

Com os comandos **`jtool -l`** ou **`otool -l`**, é possível encontrar várias seções que começam com o prefixo **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Você pode encontrar mais informações sobre as [**informações armazenadas nessas seções nesta publicação do blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Além disso, **binários Swift podem ter símbolos** (por exemplo, bibliotecas precisam armazenar símbolos para que suas funções possam ser chamadas). Os **símbolos geralmente contêm informações sobre o nome e os atributos da função de uma forma ilegível**, por isso são muito úteis; existem "**demanglers**" que podem recuperar o nome original:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Análise dinâmica

> [!WARNING]
> **Não desative o SIP como etapa padrão de depuração.** Builds de desenvolvimento com `com.apple.security.get-task-allow` podem ser depurados com o SIP ativado. Verifique o alvo com `codesign -d --entitlements :- /path/to/binary` antes de tentar usar o LLDB. Uma entitlement de debugger, por si só, não concede acesso a alvos protegidos pelo SIP.<sup>[[15]](#references)</sup>
>
> Um app distribuído com o hardened runtime geralmente não inclui `get-task-allow` e bloqueia a conexão do debugger. Se possível, use uma debug build fornecida pelo desenvolvedor; re-assinar uma cópia descartável pode alterar o comportamento em teste. Se um alvo protegido exigir que o SIP seja desativado, use uma máquina de teste dedicada ou uma VM, em vez de uma máquina da qual você dependa.<sup>[[16]](#references)</sup>
>
> Orientações anteriores para um alvo protegido em um ambiente de teste isolado listavam estas alternativas:
>
> Observe que, para depurar binários, o SIP precisa ser desativado (`csrutil disable` ou `csrutil enable --without debug`), ou os binários precisam ser copiados para uma pasta temporária e ter a assinatura removida com `codesign --remove-signature <binary-path>`, ou a depuração do binário precisa ser permitida (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Isso não é um requisito geral do SIP: prefira uma debug build e tenha em mente que copiar ou alterar uma assinatura pode modificar o comportamento em teste.

> [!WARNING]
> Observe que, para **instrumentar binários do sistema** (como `cloudconfigurationd`) no macOS, **o SIP precisa ser desativado** (apenas remover a assinatura não funcionará).

### APIs

O macOS expõe algumas APIs interessantes que fornecem informações sobre os processos:

- `proc_info`: É a principal API e fornece muitas informações sobre cada processo. É necessário ser root para obter informações sobre outros processos, mas não são necessárias entitlements especiais nem portas mach.
- `libsysmon.dylib`: Expõe informações dos processos por meio de funções XPC, mas os chamadores precisam da entitlement `com.apple.sysmond.client`.

### Stackshot e microstackshots

**Stackshotting** é uma técnica usada para capturar o estado dos processos, incluindo as call stacks de todas as threads em execução. Isso é particularmente útil para depuração, análise de desempenho e compreensão do comportamento do sistema em um momento específico. No iOS e no macOS, o stackshotting pode ser realizado com várias ferramentas e métodos, como as ferramentas **`sample`** e **`spindump`**.

### Sysdiagnose

Essa ferramenta (`/usr/bini/ysdiagnose`) basicamente coleta muitas informações do computador executando dezenas de comandos diferentes, como `ps`, `zprint`...

Ela precisa ser executada como **root**, e o daemon `/usr/libexec/sysdiagnosed` tem entitlements muito interessantes, como `com.apple.system-task-ports` e `get-task-allow`.

Seu plist está localizado em `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Exclui arquivos antigos em /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Porta especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interface em user mode por meio da classe Obj-C `Libsysdiagnose`. Três argumentos podem ser passados em um dict (`compress`, `display`, `run`)

### Logs unificados

O macOS gera logs extensos que são úteis para analisar o comportamento de um aplicativo.

Alguns campos dos logs contêm a tag `<private>` para ocultar informações que identificam o usuário ou o dispositivo. Instruções antigas às vezes descrevem a instalação de um certificado para revelar esses campos; as orientações atuais de depuração usam, em vez disso, um configuration profile com escopo explícito e `Enable-Private-Data`, ou `OSLogPreferences` por aplicativo. O comportamento pode variar conforme o subsistema e a versão do macOS. A discussão antiga sobre certificados e profiles foi mantida nas referências. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Elas não são todas as strings, mas aquelas definidas em várias partes do arquivo Mach-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, é possível ver o **código desmontado**. Também é possível visualizá-lo como desmontagem **bruta**, como **gráfico**, como **decompilado** e como **binário**, clicando no ícone correspondente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Ao clicar com o botão direito em um objeto de código, é possível ver **referências de/para esse objeto** ou até alterar seu nome (isso não funciona no pseudocódigo decompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Além disso, **na parte inferior do painel central, é possível escrever comandos Python**.

#### Painel direito

No painel direito, é possível ver informações interessantes, como o **histórico de navegação** (para saber como você chegou à situação atual), o **gráfico de chamadas**, onde é possível ver todas as **funções que chamam essa função** e todas as funções que **essa função chama**, e informações sobre **variáveis locais**.

### dtrace

Ele permite que os usuários acessem aplicativos em um nível **muito baixo** e oferece uma forma de **rastrear** **programas** e até alterar seu fluxo de execução. O DTrace usa **probes**, que são **posicionados por todo o kernel**, em locais como o início e o fim das chamadas de sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar uma probe para cada chamada de sistema. Essas probes podem ser acionadas no **ponto de entrada e de saída de cada chamada de sistema**. A interação com o DTrace ocorre por meio de /dev/dtrace, que só está disponível para o usuário root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para ativar o DTrace sem desativar completamente a proteção do SIP, você pode executar, no modo de recuperação: `csrutil enable --without dtrace`
>
> Também é possível usar **`dtrace`** ou **`dtruss`** em binários que **você compilou**.

As probes disponíveis do dtrace podem ser obtidas com:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

O nome do probe consiste em quatro partes: provider, módulo, função e nome (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o DTrace usará um curinga para essa parte.

Para configurar o DTrace para ativar probes e especificar quais ações executar quando eles forem acionados, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

- Em linha

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

É um recurso de rastreamento do kernel. Os códigos documentados podem ser encontrados em **`/usr/share/misc/trace.codes`**.

Ferramentas como `latency`, `sc_usage`, `fs_usage` e `trace` usam esse recurso internamente.

Para interagir com `kdebug`, usa-se `sysctl` no namespace `kern.kdebug`. Os MIBs a serem usados podem ser encontrados em `sys/sysctl.h`, e as funções estão implementadas em `bsd/kern/kdebug.c`.

Para interagir com kdebug usando um cliente personalizado, estas são geralmente as etapas:

- Remova as configurações existentes com KERN_KDSETREMOVE
- Configure o trace com KERN_KDSETBUF e KERN_KDSETUP
- Use KERN_KDGETBUF para obter o número de entradas do buffer
- Obtenha o próprio cliente do trace com KERN_KDPINDEX
- Ative o rastreamento com KERN_KDENABLE
- Leia o buffer chamando KERN_KDREADTR
- Para associar cada thread ao seu processo, chame KERN_KDTHRMAP.

Para obter essas informações, é possível usar a ferramenta da Apple **`trace`** ou a ferramenta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Observe que o Kdebug só está disponível para um cliente por vez.** Portanto, apenas uma ferramenta que usa k-debug pode ser executada por vez.

### ktrace

As APIs `ktrace_*` vêm de `libktrace.dylib`, que encapsula as APIs do `Kdebug`. Assim, um cliente pode simplesmente chamar `ktrace_session_create` e `ktrace_events_[single/class]` para configurar callbacks para códigos específicos e, em seguida, iniciar o rastreamento com `ktrace_start`.

Você pode usar essa ferramenta mesmo com o **SIP ativado**.

Você pode usar o utilitário `ktrace` como cliente:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ou `tailspin`.

### kperf

É usado para fazer profiling em nível de kernel e é criado usando callouts de `Kdebug`.

Basicamente, a variável global `kernel_debug_active` é verificada e, se estiver definida, chama `kperf_kdebug_handler` com o código de `Kdebug` e o endereço do frame do kernel que fez a chamada. Se o código de `Kdebug` corresponder a um dos selecionados, ele executa as “ações” configuradas como um bitmap (consulte `osfmk/kperf/action.h` para ver as opções).

Kperf também tem uma tabela MIB de sysctl: (como root) `sysctl kperf`. Esse código pode ser encontrado em `osfmk/kperf/kperfbsd.c`.

Além disso, um subconjunto das funcionalidades de Kperf está em `kpc`, que fornece informações sobre os contadores de desempenho da máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está realizando (por exemplo, monitorar quais novos processos um processo está criando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) é uma ferramenta que mostra as relações entre processos.\
Você precisa monitorar seu Mac com um comando como **`sudo eslogger fork exec rename create > cap.json`** (o Terminal que executa esse comando precisa de FDA). Depois, você pode carregar o JSON nessa ferramenta para visualizar todas as relações:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitora eventos de arquivos, como criação, modificação e exclusão.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) é uma ferramenta com GUI cujo visual e funcionamento podem ser familiares aos usuários do Windows que conhecem o _Procmon_ do Microsoft Sysinternals. Essa ferramenta permite iniciar e interromper a gravação de vários tipos de eventos, filtrar esses eventos por categorias como arquivo, processo, rede etc. e salvar os eventos gravados no formato JSON.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) faz parte das ferramentas de desenvolvimento do Xcode e é usado para monitorar o desempenho de aplicativos, identificar memory leaks e rastrear atividades do sistema de arquivos.

![Crescendo - Apple Instruments: Apple Instruments faz parte das ferramentas de desenvolvimento do Xcode e é usado para monitorar o desempenho de aplicativos, identificar memory leaks e rastrear atividades do sistema de arquivos](<../../../images/image (1138).png>)

### fs_usage

Permite acompanhar as ações realizadas pelos processos:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele usa e as conexões de **rede**.\
Ele também verifica os processos binários no **virustotal** e exibe informações sobre o binário.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Em [**esta publicação do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), você encontra um exemplo de como **depurar um daemon em execução** que usava **`PT_DENY_ATTACH`** para impedir a depuração, mesmo com o SIP desativado.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` é uma solicitação `ptrace(2)` específica do Darwin com valor **31** (`0x1f`); os outros argumentos são ignorados. Um processo pode invocá-la diretamente, sem um fork, para recusar o rastreamento posterior pelo processo pai.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Estado do XNU e ordem das chamadas

O resultado depende de qual solicitação `ptrace` chega primeiro ao XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **O LLDB se conecta primeiro:** `debugserver` usa `PT_ATTACHEXC`; o XNU converte essa solicitação em `PT_ATTACH`, realiza a autorização `KAUTH_PROCESS_CANTRACE` e define `P_LTRACED` no alvo. Uma solicitação `PT_DENY_ATTACH` subsequente encontra essa flag e encerra o alvo com `W_EXITCODE(ENOTSUP, 0)`, normalmente exibido pelo LLDB como status **45** (`0x2d`).
- **O alvo nega primeiro:** o XNU define `P_LNOATTACH`. Uma conexão posterior é rejeitada pela autorização de rastreamento de processos; o caminho de erro da conexão detecta `P_LNOATTACH` e envia `SIGSEGV` ao processo que está tentando se conectar, o que pode aparecer no LLDB como uma conexão perdida com `debugserver`.

Para distinguir esses caminhos, habilite o logging do `debugserver` antes de iniciar ou se conectar ao processo e inspecione suas solicitações `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Identificação estática e bypass em ARM64

Em um Mach-O ARM64 não ofuscado, localize o stub importado `_ptrace` e inspecione os pontos de chamada. O primeiro argumento inteiro é passado em `w0`, então essa sequência expõe diretamente a solicitação anti-debug. A ausência da importação não é conclusiva, pois o código pode resolver `ptrace` dinamicamente. Um `_sysctl` importado também pode indicar verificações anti-debug, embora ele também possa ser resolvido dinamicamente.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

No exemplo demonstrado, alterar o immediate de `0x1f` para `0x0` muda a solicitação para `PT_TRACE_ME` e permite que o programa continue sob LLDB. Este é um **bypass específico do exemplo**, não um no-op geral: inspecione as verificações do valor de retorno e o fluxo de controle do chamador antes de decidir se deve alterar a solicitação, ignorar a chamada ou forçar um retorno bem-sucedido.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** é a **ferramenta de facto** para **depuração** de binários no **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Você pode definir a sintaxe Intel ao usar lldb, criando um arquivo chamado **`.lldbinit`** na sua pasta pessoal com a seguinte linha:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dentro do lldb, despeje um processo com `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Comando</strong></td><td><strong>Descrição</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Inicia a execução, que continua até que um breakpoint seja atingido ou o processo seja encerrado.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia a execução e para no ponto de entrada.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Continua a execução do processo em depuração.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Executa a próxima instrução. Esse comando ignora as chamadas de função.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Executa a próxima instrução. Diferentemente do comando <code>nexti</code>, esse comando entra nas chamadas de função.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Executa as instruções restantes na função (frame) atual, retorna e para.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pausa a execução. Se o processo foi iniciado (<code>r</code>) ou continuado (<code>c</code>), isso faz com que ele pare onde quer que esteja sendo executado.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Exibe a memória como uma string terminada em nulo.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Exibe a memória como uma instrução assembly.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Exibe a memória como um byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Isso imprime o objeto referenciado pelo parâmetro.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
</p>A maioria das APIs ou métodos Objective-C da Apple retorna objetos e, portanto, deve ser exibida com o comando “print object” (<code>po</code>). Se <code>po</code> não produzir uma saída significativa, use <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Exibe um mapa da memória do processo atual.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Ao chamar a função **`objc_sendMsg`**, o registrador **rsi** contém o **nome do método** como uma string terminada em nulo (“C”). Para exibir o nome via lldb, faça o seguinte:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Análise dinâmica anti-debug

#### Detecção de VM

- O comando **`sysctl hw.model`** normalmente retorna um identificador de modelo Mac em hardware físico e pode retornar um valor diferente em uma VM.<sup>[[3]](#references)</sup>
- Ao alterar os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se estão em uma VM.<sup>[[4]](#references)</sup>
- Um loader também pode consultar `kern.hv_vmm_present` e `machdep.cpu.brand_string` por meio de `sysctl` ao verificar se está em uma VM antes de desempacotar o próximo estágio. Essas verificações complementam, mas não substituem, a verificação de conexão do debugger descrita abaixo.<sup>[[20]](#references)</sup>
- Alguns malwares também conseguem **detectar** se a máquina é baseada em **VMware** usando o endereço MAC (00:50:56).
- Também é possível descobrir **se um processo está sendo depurado** com um código simples como:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Também pode invocar a chamada de sistema `ptrace` com a flag `PT_DENY_ATTACH`. Isso impede que um debugger se conecte e faça tracing. Consulte a [seção PT_DENY_ATTACH](#page-title) para ver o comportamento do XNU, dependente da ordem, o logging de `debugserver` e o fluxo de trabalho de patching em ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
- Também pode invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Consulte a [seção PT_DENY_ATTACH](#page-title) para ver o comportamento do XNU, dependente da ordem, o logging de `debugserver` e o fluxo de trabalho de patching em ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
  - Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
  - Como observado neste writeup, “[Derrotando técnicas anti-debug: variantes de macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_A mensagem Process # exited with **status = 45 (0x0000002d)** geralmente é um indício claro de que o alvo do debug está usando **PT_DENY_ATTACH**_”
#### Transferência do processo `fork()`

Um processo pode escapar de um debugger que continua conectado ao PID original chamando `fork()` no início, encerrando o processo pai (`fork()` retorna um PID positivo do filho) e continuando a lógica protegida apenas no filho (`fork()` retorna `0`). Resolver `fork` com `dlsym(RTLD_DEFAULT, "fork")` também remove o ponto de chamada direto de `_fork`, mas isso é apenas um obstáculo à análise: a string com o nome do símbolo e o fluxo de dados de resolução dinâmica continuam visíveis no binário Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Em arm64, detecte esse padrão acompanhando o fluxo de dados, em vez de endereços fixos: os dois primeiros argumentos de `dlsym` são passados em `x0` e `x1`, `RTLD_DEFAULT` pode aparecer como `-2` (por exemplo, `movn x0, #1`), e um par `adrp`/`add` geralmente constrói o endereço da string `"fork"`. Após o `bl` para o stub de `dlsym`, acompanhe o ponteiro retornado de `x0` por sua verificação de nulo e seu armazenamento até um `blr` indireto posterior. Em seguida, acompanhe o resultado de `fork()` em `w0`: zero seleciona a continuação do filho, enquanto valores positivos e `-1` selecionam o caminho do pai/erro.<sup>[[13]](#references)[[14]](#references)</sup>

Uma forma de bypass estático é suprimir a chamada indireta e forçar a verificação do resultado existente a seguir o caminho do filho. Por exemplo, se o compilador gerou a sequência mostrada abaixo, aplique patch no `blr` e no armazenamento do resultado com `nop`, forneça um resultado sintético zero e mantenha a lógica de comparação/branch. O aplicativo continua então sob o PID original, sem criar um processo filho; os registradores de instrução e os destinos dos branches devem ser adaptados à build analisada.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Os core dumps são criados se:

- O sysctl `kern.coredump` estiver definido como 1 (valor padrão)
- Se o processo não for suid/sgid ou `kern.sugid_coredump` estiver definido como 1 (o valor padrão é 0)
- O limite `AS_CORE` permitir a operação. É possível impedir a criação de core dumps chamando `ulimit -c 0` e reativá-la com `ulimit -c unlimited`.

Nesses casos, os core dumps são gerados de acordo com o sysctl `kern.corefile` e geralmente armazenados em `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

O ReportCrash **analisa processos que falham e salva um relatório de falha em disco**. Um relatório de falha contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de uma falha.\
Para aplicativos e outros processos **em execução no contexto launchd do usuário**, o ReportCrash é executado como um LaunchAgent e salva os relatórios de falha em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **em execução no contexto launchd do sistema** e outros processos privilegiados, o ReportCrash é executado como um LaunchDaemon e salva os relatórios de falha em `/Library/Logs/DiagnosticReports` do sistema.

Se você estiver preocupado com o envio de relatórios de falha **para a Apple**, poderá desativá-los. Caso contrário, os relatórios de falha podem ser úteis para **descobrir como um servidor falhou**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Suspensão

Ao fazer fuzzing no macOS, impeça o Mac de suspender:

- systemsetup -setsleep Never
- pmset, Preferências do Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se você estiver fazendo fuzzing por meio de uma conexão SSH, é importante garantir que a sessão não seja encerrada. Portanto, altere o arquivo sshd_config com:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Manipuladores Internos

**Consulte a página a seguir** para descobrir como identificar qual app é responsável por **tratar o esquema ou protocolo especificado:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerando Processos de Rede

Isso é útil para encontrar processos que gerenciam dados de rede:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ou use `netstat` ou `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing de Mach IPC com estado

Os serviços Mach expostos por daemons privilegiados são alvos úteis para fuzzing quando um cliente sem privilégios ou em sandbox consegue obter um send right. Comece pela entrada `MachServices` do launchd do daemon e use o [fluxo de análise do MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) para mapear os IDs das mensagens aos handlers. Antes de alterar bytes, defina um breakpoint na rotina do servidor MIG enquanto um cliente normal usa o serviço e salve mensagens de solicitação válidas como inputs iniciais. Preserve os campos obrigatórios do cabeçalho, os tamanhos das mensagens e o layout dos descritores para que as mutações cheguem ao handler em vez de falharem imediatamente no dispatch.<sup>[[17]](#references)</sup>

Muitos handlers dependem de chamadas anteriores. Faça o harness inicializar o estado do serviço e, em seguida, consumir cada input de fuzzing como uma sequência de **operações e argumentos**: envie solicitações de configuração (como abrir ou criar), retenha os identificadores retornados e use-os em solicitações posteriores. Isso permite que o feedback de cobertura explore transições de estado em vez de atingir repetidamente uma verificação de objeto não inicializado.<sup>[[17]](#references)</sup>

Para um alvo de código fechado, um harness in-process que chama a rotina de dispatch do MIG pode ser instrumentado com Jackalope/TinyInst. O [harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) é uma implementação concreta, não um harness pronto para uso em outros serviços.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Valide cada crash pelo caminho IPC real.** Um harness de dispatch direto ignora a validação de mensagens Mach pelo kernel e pode produzir falsos positivos, especialmente quando fornece memória out-of-line (OOL) ou descritores de porta inválidos. Aloque memória OOL válida de suporte no harness e, em seguida, reproduza o testcase reduzido por meio de `mach_msg`, a partir de um cliente com o acesso original ao serviço, e confirme que o daemon ainda trava.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona com ferramentas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

"**Simplesmente funciona**" com muitas ferramentas GUI do macOS. Alguns aplicativos têm requisitos adicionais, como nomes de arquivo exclusivos, uma extensão específica ou a leitura de arquivos do contêiner de sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Alguns exemplos:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Mais informações sobre fuzzing do macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Resposta a incidentes no OS X: scripting e análise](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - AppSec Village da DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [A arte do malware para Mac, Volume I: análise](https://taomm.org/)
- [4] [No Starch Press - A arte do malware para Mac: guia para analisar software malicioso](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informações armazenadas nestas seções desta postagem do blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - depurando binários da Apple que usam Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - contornando técnicas anti-debug: variantes de ptrace no macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Fóruns Apple Developer - logs estruturados do Xcode e `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - exibindo dados privados no log unificado do macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Definições de solicitações de `ptrace.h` do Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Implementação de `ptrace` do Apple XNU em `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - internals de ptrace: como ele impede a conexão de depuradores](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - exemplos de fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - técnica anti-debug usando dlsym e fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - entitlement de ferramenta de debugging](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Fóruns Apple Developer - depurando um app de terceiros com hardened runtime](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - quebrando a barreira do som, parte I: fuzzing do CoreAudio com mensagens Mach](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - harness do CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - nova versão do stealer MacSync para macOS tem como alvo entusiastas de criptomoedas e desenvolvedores](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
