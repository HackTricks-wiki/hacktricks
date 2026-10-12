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

### Disarm (old jtool2)

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
> **`Codesign`** pode ser encontrado no **macOS**, enquanto **`ldid`** pode ser encontrado no **iOS**

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que há dentro deles antes de instalá-los.\
Esses instaladores têm scripts bash `preinstall` e `postinstall` que autores de malware costumam abusar para **persistir** **o** **malware**.

### hdiutil

Esta ferramenta **monta** arquivos de imagem de disco da Apple (`.dmg`) para que possam ser inspecionados antes de qualquer coisa ser executada:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Será montado em `/Volumes`

### Binários empacotados

- Verifique se há alta entropia
- Verifique as strings (se quase não houver strings compreensíveis, o binário está empacotado)
- O packer UPX para macOS gera uma seção chamada `__XHDR`.

## Análise estática de Objective-C

### Metadados

> [!CAUTION]
> Observe que programas escritos em Objective-C **mantêm** suas declarações de classe **quando são** **compilados** em [binários Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Essas declarações de classe **incluem** o nome e o tipo de:

- As interfaces definidas
- Os métodos das interfaces
- As variáveis de instância das interfaces
- Os protocolos definidos

Observe que esses nomes podem ser ofuscados para dificultar a engenharia reversa do binário.

### Chamadas de função

Quando uma função é chamada em um binário que usa Objective-C, em vez de chamar essa função, o código compilado chamará **`objc_msgSend`**, que chamará a função final:

![Metadados - Chamadas de função: Quando uma função é chamada em um binário que usa Objective-C, em vez de chamar essa função, o código compilado chamará objc msgSend . Que chamará...](<../../../images/image (305).png>)

Os parâmetros esperados por essa função são:

- O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que deve receber a mensagem**". Ou, de forma mais simples, é o objeto sobre o qual o método é invocado. Se o método for um método de classe, esse parâmetro será uma instância do objeto de classe (como um todo); para um método de instância, self apontará para uma instância da classe instanciada como objeto.
- O segundo parâmetro (**op**) é "o seletor do método que trata a mensagem". De forma mais simples, é apenas o **nome do método**.
- Os parâmetros restantes são quaisquer **valores exigidos pelo método** (op).

Veja nesta página como **obter essas informações facilmente com `lldb` em ARM64**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**       | **Registrador**                                                 | **(para) objc_msgSend**                                |
| ------------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1º argumento**    | **rdi**                                                         | **self: objeto sobre o qual o método é invocado**      |
| **2º argumento**    | **rsi**                                                         | **op: nome do método**                                 |
| **3º argumento**    | **rdx**                                                         | **1º argumento do método**                             |
| **4º argumento**    | **rcx**                                                         | **2º argumento do método**                             |
| **5º argumento**    | **r8**                                                          | **3º argumento do método**                             |
| **6º argumento**    | **r9**                                                          | **4º argumento do método**                             |
| **7º argumento em diante** | <p><strong>rsp+</strong><br><strong>(na pilha)</strong></p> | **5º argumento do método em diante**                   |

### Despejar metadados de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) é uma ferramenta para extrair o dump de classes de binários Objective-C. O GitHub menciona dylibs, mas a ferramenta também funciona com executáveis.

```bash
./dynadump dump /path/to/bin
```

Na época em que este texto foi escrito, esta é **atualmente a opção que funciona melhor**.

#### Ferramentas convencionais

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) é a ferramenta original para gerar declarações das classes, categorias e protocolos em código Objective-C formatado.

É antiga e não é mantida, então provavelmente não funcionará corretamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) é uma ferramenta moderna e multiplataforma para fazer dump de classes Objective-C. Em comparação com as ferramentas existentes, o iCDump pode ser executado independentemente do ecossistema Apple e disponibiliza bindings Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Análise estática de Swift

Com binários Swift, devido à compatibilidade com Objective-C, às vezes é possível extrair declarações usando [class-dump](https://github.com/nygard/class-dump/), mas nem sempre.

Com as linhas de comando **`jtool -l`** ou **`otool -l`**, é possível encontrar várias seções que começam com o prefixo **`__swift5`**:

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

Além disso, **binários Swift podem conter símbolos** (por exemplo, bibliotecas precisam armazenar símbolos para que suas funções possam ser chamadas). Os **símbolos geralmente contêm informações sobre o nome e os atributos da função** em um formato pouco legível, por isso são muito úteis; existem "**demanglers"** que podem recuperar o nome original:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Análise Dinâmica

> [!WARNING]
> Observe que, para depurar binários, **o SIP precisa estar desativado** (`csrutil disable` ou `csrutil enable --without debug`), ou você precisa copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <binary-path>`, ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Observe que, para **instrumentar binários do sistema** (como `cloudconfigurationd`) no macOS, **o SIP precisa estar desativado** (apenas remover a assinatura não funcionará).

### APIs

O macOS expõe algumas APIs interessantes que fornecem informações sobre os processos:

- `proc_info`: É a principal API e fornece muitas informações sobre cada processo. Você precisa ser root para obter informações sobre outros processos, mas não precisa de entitlements especiais nem de portas mach.
- `libsysmon.dylib`: Expõe informações sobre processos por meio de funções XPC, mas os chamadores precisam do entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** é uma técnica usada para capturar o estado dos processos, incluindo as pilhas de chamadas de todas as threads em execução. Isso é particularmente útil para depuração, análise de desempenho e compreensão do comportamento do sistema em um determinado momento. No iOS e no macOS, o stackshotting pode ser realizado usando várias ferramentas e métodos, como as ferramentas **`sample`** e **`spindump`**.

### Sysdiagnose

Essa ferramenta (`/usr/bini/ysdiagnose`) basicamente coleta muitas informações do seu computador, executando dezenas de comandos diferentes, como `ps`, `zprint`...

Ela precisa ser executada como **root**, e o daemon `/usr/libexec/sysdiagnosed` tem entitlements muito interessantes, como `com.apple.system-task-ports` e `get-task-allow`.

Seu plist está localizado em `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Exclui arquivos antigos em /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Porta especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interface em modo de usuário por meio da classe Obj-C `Libsysdiagnose`. É possível passar três argumentos em um dict (`compress`, `display`, `run`)

### Logs Unificados

O macOS gera logs extensos que são úteis ao analisar o comportamento de um aplicativo.

Alguns campos de log contêm a tag `<private>` para ocultar informações que identificam o usuário ou o dispositivo. Instruções antigas às vezes descrevem a instalação de um certificado para revelar esses campos; as orientações atuais de depuração usam, em vez disso, um perfil de configuração explicitamente delimitado com `Enable-Private-Data` ou `OSLogPreferences` por aplicativo, e o comportamento pode variar conforme o subsistema e a versão do macOS. A discussão antiga sobre certificados/perfis foi mantida nas referências. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas as definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, você pode ver o **código desmontado**. Também é possível visualizá-lo como desmontagem **bruta**, como **gráfico**, como **decompilado** e como **binário**, clicando no ícone correspondente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Ao clicar com o botão direito em um objeto de código, você pode ver **referências de/para esse objeto** ou até mesmo alterar seu nome (isso não funciona no pseudocódigo decompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Além disso, **na parte inferior do painel central, você pode escrever comandos Python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como chegou à situação atual), o **grafo de chamadas**, onde é possível ver todas as **funções que chamam esta função** e todas as funções que **esta função chama**, além de informações sobre **variáveis locais**.

### dtrace

Ele permite que os usuários acessem aplicativos em um nível **muito baixo** e oferece uma maneira de **rastrear** **programas** e até mesmo alterar seu fluxo de execução. O DTrace usa **probes** **distribuídos pelo kernel**, em locais como o início e o fim de chamadas de sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar um probe para cada chamada de sistema. Esses probes podem ser acionados no **ponto de entrada e no ponto de saída de cada chamada de sistema**. A interação com o DTrace ocorre por meio de /dev/dtrace, que está disponível apenas para o usuário root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para habilitar o Dtrace sem desativar completamente a proteção do SIP, você pode executar no modo de recuperação: `csrutil enable --without dtrace`
>
> Você também pode usar **`dtrace`** ou **`dtruss`** em binários que **você compilou**.

Os probes disponíveis do dtrace podem ser obtidos com:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

O nome do probe consiste em quatro partes: provider, module, function e name (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o DTrace usará essa parte como curinga.

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

Ferramentas como `latency`, `sc_usage`, `fs_usage` e `trace` o utilizam internamente.

Para interagir com `kdebug`, usa-se `sysctl` no namespace `kern.kdebug`; os MIBs a utilizar podem ser encontrados em `sys/sysctl.h`, com as funções implementadas em `bsd/kern/kdebug.c`.

Para interagir com kdebug usando um cliente personalizado, estes são geralmente os passos:

- Remover as configurações existentes com KERN_KDSETREMOVE
- Configurar o trace com KERN_KDSETBUF e KERN_KDSETUP
- Usar KERN_KDGETBUF para obter o número de entradas do buffer
- Obter o próprio cliente do trace com KERN_KDPINDEX
- Ativar o rastreamento com KERN_KDENABLE
- Ler o buffer chamando KERN_KDREADTR
- Para associar cada thread ao seu processo, chamar KERN_KDTHRMAP.

Para obter essas informações, é possível usar a ferramenta da Apple **`trace`** ou a ferramenta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Observe que o Kdebug só está disponível para 1 cliente por vez.** Portanto, apenas uma ferramenta baseada em k-debug pode ser executada de cada vez.

### ktrace

As APIs `ktrace_*` vêm de `libktrace.dylib`, que encapsula as APIs de `Kdebug`. Assim, um cliente pode simplesmente chamar `ktrace_session_create` e `ktrace_events_[single/class]` para definir callbacks para códigos específicos e, em seguida, iniciar o rastreamento com `ktrace_start`.

Você pode usar essa ferramenta mesmo com o **SIP ativado**

Você pode usar o utilitário `ktrace` como cliente:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ou `tailspin`.

### kperf

É usado para fazer profiling em nível de kernel e é construído usando callouts do `Kdebug`.

Basicamente, a variável global `kernel_debug_active` é verificada e, se estiver definida, chama `kperf_kdebug_handler` com o código `Kdebug` e o endereço do frame do kernel que fez a chamada. Se o código `Kdebug` corresponder a um dos selecionados, são aplicadas as “ações” configuradas como um bitmap (consulte `osfmk/kperf/action.h` para ver as opções).

O Kperf também tem uma tabela MIB de sysctl: (como root) `sysctl kperf`. Esse código pode ser encontrado em `osfmk/kperf/kperfbsd.c`.

Além disso, um subconjunto das funcionalidades do Kperf está em `kpc`, que fornece informações sobre os contadores de desempenho da máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está realizando (por exemplo, monitorar quais processos novos um processo está criando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) é uma ferramenta que exibe as relações entre processos.\
Você precisa monitorar seu Mac com um comando como **`sudo eslogger fork exec rename create > cap.json`** (o Terminal que executar esse comando precisa de FDA). Depois, você pode carregar o JSON nessa ferramenta para visualizar todas as relações:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitora eventos de arquivos, como criação, modificação e exclusão.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) é uma ferramenta com interface gráfica cujo visual e funcionamento podem ser familiares aos usuários do Windows por causa do _Procmon_ do Microsoft Sysinternals. Essa ferramenta permite iniciar e parar a gravação de vários tipos de eventos, filtrar esses eventos por categorias como arquivo, processo, rede etc. e salvar os eventos gravados no formato JSON.

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

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele está usando e as conexões de **rede**.\
Ele também verifica os processos binários no **virustotal** e exibe informações sobre o binário.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Em [**esta publicação do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) você pode encontrar um exemplo de como **depurar um daemon em execução** que usava **`PT_DENY_ATTACH`** para impedir a depuração mesmo com o SIP desativado.<sup>[[6]](#references)</sup>

### lldb

**lldb** é a ferramenta de facto para **depuração** de binários do **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Você pode definir o estilo Intel ao usar o lldb, criando um arquivo chamado **`.lldbinit`** na sua pasta pessoal com a seguinte linha:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dentro do lldb, despeje um processo com `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>Comando (lldb)</strong></td><td><strong>Descrição</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Inicia a execução, que continuará até que um breakpoint seja atingido ou o processo termine.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia a execução e para no ponto de entrada.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Continua a execução do processo depurado.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Executa a próxima instrução. Este comando não entra em chamadas de função.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Executa a próxima instrução. Diferentemente do comando <code>nexti</code>, este comando entra em chamadas de função.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Executa as instruções restantes na função (frame) atual, retorna e para.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pausa a execução. Se o processo tiver sido iniciado (<code>r</code>) ou continuado (<code>c</code>), isso fará com que ele pare onde estiver executando.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Qualquer função chamada main</p>
<p><code>b &lt;binname&gt;`main</code> # Função principal do binário</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Função principal do binário indicado</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Qualquer método de NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break em todas as funções dessa biblioteca</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista de breakpoints</p>
<p><code>br e/dis &lt;num&gt;</code> # Ativa/desativa breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Obtém ajuda para o comando breakpoint</p>
<p><code>help memory write</code> # Obtém ajuda para gravações na memória</p>
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
<p>Imprime o objeto referenciado pelo parâmetro.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
A maioria das APIs ou métodos Objective-C da Apple retorna objetos e, portanto, deve ser exibida com o comando “print object” (<code>po</code>). Se <code>po</code> não produzir uma saída significativa, use <code>x/b</code>.</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Grava AAAA nesse endereço<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Grava AAAA no endereço
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Desmonta a função atual</p>
<p><code>dis -n &lt;funcname&gt;</code> # Desmonta uma função</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Desmonta uma função<br>
<code>dis -c 6</code> # Desmonta seis linhas<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Desmonta do endereço inicial ao final<br>
<code>dis -p -c 4</code> # Começa a desmontar no endereço atual</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspeciona um array com três componentes no registrador <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Imprime um mapa da memória do processo atual.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Obtém o endereço de cada símbolo de CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Ao chamar a função **`objc_sendMsg`**, o registrador **rsi** contém o **nome do método** como uma string terminada em nulo (“C”). Para imprimir o nome via lldb, execute:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Análise Dinâmica

#### Detecção de VM

- O comando **`sysctl hw.model`** normalmente retorna um identificador de modelo de Mac em hardware físico e pode retornar um valor diferente em uma VM.<sup>[[3]](#references)</sup>
- Alterando os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se estão em uma VM.<sup>[[4]](#references)</sup>
- Alguns malwares também conseguem **detectar** se a máquina é baseada em **VMware** pelo endereço MAC (00:50:56).
- Também é possível descobrir **se um processo está sendo depurado** com um código simples como:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Também pode invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** que um deb**u**gger se conecte e rastreie o processo.
  - Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
  - Como observado neste writeup, “[Derrotando técnicas anti-debug: variantes de macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_A mensagem Process # exited with **status = 45 (0x0000002d)** costuma ser um sinal evidente de que o alvo da depuração está usando **PT_DENY_ATTACH**_”

#### Transferência do processo `fork()`

Um processo pode escapar de um debugger que permanece conectado ao PID original chamando `fork()` perto da inicialização, encerrando o processo pai (`fork()` retorna um PID positivo do filho) e continuando a lógica protegida apenas no filho (`fork()` retorna `0`). Resolver `fork` com `dlsym(RTLD_DEFAULT, "fork")` também remove o ponto de chamada direto `_fork`, mas isso é apenas um obstáculo à análise: a string com o nome do símbolo e o fluxo de dados da resolução dinâmica continuam visíveis no binário Mach-O.<sup>[[10]](#references)[[11]](#references)</sup>

No arm64, detecte esse padrão acompanhando o fluxo de dados, em vez de endereços fixos: os dois primeiros argumentos para `dlsym` são passados em `x0` e `x1`, `RTLD_DEFAULT` pode aparecer como `-2` (por exemplo, `movn x0, #1`), e um par `adrp`/`add` costuma construir o endereço da string `"fork"`. Depois do `bl` para o stub de `dlsym`, acompanhe o ponteiro retornado de `x0` através da verificação de nulo e do armazenamento até um `blr` indireto posterior. Em seguida, acompanhe o resultado de `fork()` em `w0`: zero direciona para a continuação do filho, enquanto valores positivos e `-1` direcionam para o caminho do pai/erro.<sup>[[10]](#references)[[11]](#references)</sup>

Um bypass estático consiste em suprimir a chamada indireta e forçar a verificação do resultado existente a seguir o caminho do filho. Por exemplo, se o compilador gerar a sequência mostrada abaixo, aplique patch em `blr` e no armazenamento do resultado com `nop`, forneça um resultado zero sintético e mantenha a lógica de comparação/desvio. Assim, o aplicativo continua sob o PID original sem criar um processo filho; os registradores de instrução e os destinos dos desvios devem ser adaptados à build analisada.<sup>[[10]](#references)[[11]](#references)</sup>

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

- O sysctl `kern.coredump` estiver definido como 1 (por padrão)
- Se o processo não for suid/sgid ou `kern.sugid_coredump` estiver definido como 1 (por padrão, é 0)
- O limite `AS_CORE` permitir a operação. É possível impedir a criação de core dumps chamando `ulimit -c 0` e reativá-la com `ulimit -c unlimited`.

Nesses casos, os core dumps são gerados de acordo com o sysctl `kern.corefile` e geralmente armazenados em `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

O ReportCrash **analisa processos que falharam e salva um relatório de falha em disco**. Um relatório de falha contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de uma falha.\
Para aplicativos e outros processos **em execução no contexto do launchd por usuário**, o ReportCrash é executado como LaunchAgent e salva os relatórios de falha em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **em execução no contexto do launchd do sistema** e outros processos privilegiados, o ReportCrash é executado como LaunchDaemon e salva os relatórios de falha em `/Library/Logs/DiagnosticReports` do sistema.

Se você estiver preocupado com o envio de relatórios de falha **para a Apple**, pode desativá-los. Caso contrário, os relatórios de falha podem ser úteis para **descobrir como um servidor falhou**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Suspensão

Durante fuzzing no macOS, impeça o Mac de entrar em suspensão:

- systemsetup -setsleep Never
- pmset, Preferências do Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se estiver fazendo fuzzing por meio de uma conexão SSH, é importante garantir que a sessão não seja encerrada. Portanto, altere o arquivo sshd_config com:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Manipuladores internos

**Consulte a página a seguir** para descobrir como identificar qual app é responsável por **tratar o esquema ou protocolo especificado:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerando processos de rede

Isso é interessante para encontrar processos que gerenciam dados de rede:

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

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona com ferramentas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Ele "**simplesmente funciona**" com muitas ferramentas GUI do macOS. Algumas aplicações têm requisitos adicionais, como nomes de arquivo exclusivos, uma extensão específica ou a leitura de arquivos do contêiner de sandbox (`~/Library/Containers/com.apple.Safari/Data`).

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

### Mais informações sobre Fuzzing no macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Resposta a incidentes no OS X: scripting e análise](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Verão de Fuzz: MacOS - AppSec Village da DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [A arte do malware para Mac, Volume I: análise](https://taomm.org/)
- [4] [No Starch Press - A arte do malware para Mac: guia para analisar software malicioso](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informações armazenadas nessas seções desta publicação do blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - depuração de binários da Apple que usam Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - como derrotar técnicas anti-debug: variantes de ptrace no macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Fóruns para desenvolvedores da Apple - logs estruturados do Xcode e `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - exibição de dados privados no log unificado do macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - exemplos de fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - técnica anti-debugging usando dlsym e fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
