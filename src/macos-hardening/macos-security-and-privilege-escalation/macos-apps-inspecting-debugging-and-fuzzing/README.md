# Apps do macOS - Inspeção, debugging e Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Análise Estática

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
> Observe que o **`disarm`** também pode funcionar com arquivos IM4P compactados (como `kernelcache`) e extrair apenas as partes necessárias ou até mesmo analisar a parte necessária sem extraí-la.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e verificar o que há dentro deles antes de instalá-los.\
Esses instaladores têm scripts bash `preinstall` e `postinstall` que autores de malware geralmente abusam para **persistir** **o** **malware**.

### hdiutil

Essa ferramenta permite **montar** arquivos de imagens de disco da Apple (**.dmg**) para inspecioná-los antes de executar qualquer coisa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Ele será montado em `/Volumes`

### Binários compactados

- Verifique se há alta entropia
- Verifique as strings (se quase não houver nenhuma string compreensível, o binário está compactado)
- O packer UPX para MacOS gera uma seção chamada "\_\_XHDR"

## Análise estática de Objective-C

### Metadados

> [!CAUTION]
> Observe que os programas escritos em Objective-C **mantêm** suas declarações de classe **quando** são **compilados** em [binários Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Essas declarações de classe **incluem** o nome e o tipo de:

- As interfaces definidas
- Os métodos das interfaces
- As variáveis de instância das interfaces
- Os protocolos definidos

Observe que esses nomes podem ser ofuscados para dificultar o reversing do binário.

### Chamada de funções

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará **`objc_msgSend`**, que chamará a função final:

![Metadados - Chamada de funções: quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará objc msgSend, que será...](<../../../images/image (305).png>)

Os parâmetros esperados por essa função são:

- O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que deve receber a mensagem**". Ou, de forma mais simples, é o objeto sobre o qual o método está sendo invocado. Se o método for um método de classe, ele será uma instância do objeto de classe (como um todo), enquanto, para um método de instância, self apontará para uma instância criada da classe como um objeto.
- O segundo parâmetro, (**op**), é "o selector do método que trata a mensagem". Novamente, de forma mais simples, este é apenas o **nome do método.**
- Os parâmetros restantes são quaisquer **valores exigidos pelo método** (op).

Veja como **obter essas informações facilmente com `lldb` em ARM64** nesta página:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**      | **Registrador**                                                | **(para) objc_msgSend**                                  |
| ------------------ | -------------------------------------------------------------- | -------------------------------------------------------- |
| **1º argumento**   | **rdi**                                                         | **self: objeto sobre o qual o método está sendo invocado** |
| **2º argumento**   | **rsi**                                                         | **op: nome do método**                                   |
| **3º argumento**   | **rdx**                                                         | **1º argumento do método**                               |
| **4º argumento**   | **rcx**                                                         | **2º argumento do método**                               |
| **5º argumento**   | **r8**                                                          | **3º argumento do método**                               |
| **6º argumento**   | **r9**                                                          | **4º argumento do método**                               |
| **7º+ argumento**  | <p><strong>rsp+</strong><br><strong>(na stack)</strong></p>    | **5º+ argumento do método**                             |

### Dump de metadados de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) é uma ferramenta para class-dump de binários Objective-C. O github especifica dylibs, mas isso também funciona com executáveis.
```bash
./dynadump dump /path/to/bin
```
No momento da redação, este é **atualmente o que funciona melhor**.

#### Ferramentas comuns
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) é a ferramenta original para gerar declarações das classes, categorias e protocolos em código formatado de Objective-C.

É antiga e não é mantida, portanto provavelmente não funcionará corretamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) é uma ferramenta moderna e multiplataforma para class dump de Objective-C. Comparada às ferramentas existentes, a iCDump pode ser executada independentemente do ecossistema da Apple e disponibiliza bindings para Python.
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

Além disso, **os binários Swift podem conter symbols** (por exemplo, as bibliotecas precisam armazenar symbols para que suas funções possam ser chamadas). Os **symbols geralmente contêm informações sobre o nome da função** e seus atributos de uma forma desagradável, portanto são muito úteis, e existem "**demanglers"** que podem obter o nome original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Análise Dinâmica

> [!WARNING]
> Observe que, para depurar binários, o **SIP precisa ser desativado** (`csrutil disable` ou `csrutil enable --without debug`) ou é necessário copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <binary-path>` ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Observe que, para **instrumentar binários do sistema**, (como `cloudconfigurationd`) no macOS, o **SIP precisa estar desativado** (apenas remover a assinatura não funcionará).

### APIs

O macOS expõe algumas APIs interessantes que fornecem informações sobre os processos:

- `proc_info`: Esta é a principal, fornecendo muitas informações sobre cada processo. Você precisa ser root para obter informações sobre outros processos, mas não precisa de entitlements especiais ou portas mach.
- `libsysmon.dylib`: Permite obter informações sobre processos por meio de funções expostas via XPC; no entanto, é necessário possuir o entitlement `com.apple.sysmond.client`.

### Stackshot e microstackshots

**Stackshotting** é uma técnica usada para capturar o estado dos processos, incluindo as call stacks de todas as threads em execução. Isso é particularmente útil para depuração, análise de desempenho e compreensão do comportamento do sistema em um ponto específico no tempo. No iOS e no macOS, stackshotting pode ser realizado usando várias ferramentas e métodos, como as ferramentas **`sample`** e **`spindump`**.

### Sysdiagnose

Esta ferramenta (`/usr/bini/ysdiagnose`) basicamente coleta muitas informações do seu computador, executando dezenas de comandos diferentes, como `ps`, `zprint`...

Ela deve ser executada como **root**, e o daemon `/usr/libexec/sysdiagnosed` possui entitlements muito interessantes, como `com.apple.system-task-ports` e `get-task-allow`.

Seu plist está localizado em `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Exclui arquivos antigos em /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Porta especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interface em modo de usuário por meio da classe Obj-C `Libsysdiagnose`. Três argumentos em um dict podem ser fornecidos (`compress`, `display`, `run`)

### Unified Logs

O MacOS gera muitos logs que podem ser muito úteis ao executar um aplicativo e tentar entender **o que ele está fazendo**.

Além disso, existem alguns logs que contêm a tag `<private>` para **ocultar** algumas informações **identificáveis** do **usuário** ou do **computador**. No entanto, é possível **instalar um certificado para revelar essas informações**. Siga as explicações [aqui](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas aquelas definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, você pode ver o **código dissasembled**. Também é possível visualizá-lo como um disassembly **raw**, como **graph**, como **decompiled** e como **binary**, clicando no ícone correspondente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Clicando com o botão direito em um objeto de código, você pode ver **referências de/para esse objeto** ou até mesmo alterar seu nome (isso não funciona no pseudocódigo decompiled):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Além disso, **na parte inferior central, você pode escrever comandos python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como chegou à situação atual), o **call grap**h, onde pode ver todas as **funções que chamam esta função** e todas as funções que **esta função chama**, além de informações sobre **variáveis locais**.

### dtrace

Ele permite que os usuários acessem aplicativos em um nível **extremamente baixo** e oferece uma forma de **rastrear** **programas** e até alterar seu fluxo de execução. O Dtrace usa **probes**, que são **posicionados em todo o kernel** e ficam em locais como o início e o fim das chamadas de sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar uma probe para cada chamada de sistema. Essas probes podem ser acionadas no **ponto de entrada e saída de cada chamada de sistema**. A interação com o DTrace ocorre por meio de /dev/dtrace, que só está disponível para o usuário root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para habilitar o Dtrace sem desativar totalmente a proteção do SIP, você pode executar no modo de recuperação: `csrutil enable --without dtrace`
>
> Você também pode usar **`dtrace`** ou **`dtruss`** em binários que **você compilou**.

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
O nome do probe consiste em quatro partes: o provider, o module, a function e o name (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do name, o DTrace aplicará essa parte como um wildcard.

Para configurar o DTrace para ativar probes e especificar quais ações executar quando eles forem disparados, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts do DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

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

É uma facility de tracing do kernel. Os códigos documentados podem ser encontrados em **`/usr/share/misc/trace.codes`**.

Ferramentas como `latency`, `sc_usage`, `fs_usage` e `trace` usam isso internamente.

Para fazer interface com `kdebug`, `sysctl` é usado no namespace `kern.kdebug`, e as MIBs a serem usadas podem ser encontradas em `sys/sysctl.h`, com as funções implementadas em `bsd/kern/kdebug.c`.

Para interagir com o kdebug usando um cliente customizado, estes são geralmente os passos:

- Remover as configurações existentes com KERN_KDSETREMOVE
- Configurar o trace com KERN_KDSETBUF e KERN_KDSETUP
- Usar KERN_KDGETBUF para obter o número de entradas do buffer
- Remover o próprio cliente do trace com KERN_KDPINDEX
- Habilitar o tracing com KERN_KDENABLE
- Ler o buffer chamando KERN_KDREADTR
- Associar cada thread ao seu processo usando KERN_KDTHRMAP.

Para obter essas informações, é possível usar a ferramenta da Apple **`trace`** ou a ferramenta customizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Observe que o Kdebug só está disponível para 1 cliente por vez.** Portanto, apenas uma ferramenta baseada em k-debug pode ser executada simultaneamente.

### ktrace

As APIs `ktrace_*` vêm de `libktrace.dylib`, que encapsula as APIs do `Kdebug`. Assim, um cliente pode simplesmente chamar `ktrace_session_create` e `ktrace_events_[single/class]` para configurar callbacks em códigos específicos e, em seguida, iniciar o processo com `ktrace_start`.

Você pode usar esta ferramenta mesmo com o **SIP ativado**

Você pode usar o utilitário `ktrace` como cliente:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ou `tailspin`.

### kperf

Isso é usado para fazer profiling em nível de kernel e é construído usando callouts de `Kdebug`.

Basicamente, a variável global `kernel_debug_active` é verificada e, se estiver definida, chama `kperf_kdebug_handler` com o código de `Kdebug` e o endereço do frame do kernel que está fazendo a chamada. Se o código de `Kdebug` corresponder a um dos selecionados, ele obtém as "ações" configuradas como um bitmap (consulte `osfmk/kperf/action.h` para ver as opções).

O Kperf também possui uma tabela MIB de sysctl: (como root) `sysctl kperf`. Esses códigos podem ser encontrados em `osfmk/kperf/kperfbsd.c`.

Além disso, um subconjunto das funcionalidades do Kperf está em `kpc`, que fornece informações sobre os contadores de desempenho da máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está executando (por exemplo, monitorar quais novos processos um processo está criando).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) é uma ferramenta que exibe as relações entre processos.\
Você precisa monitorar seu Mac com um comando como **`sudo eslogger fork exec rename create > cap.json`** (o terminal que executa esse comando requer FDA). Depois, você pode carregar o json nessa ferramenta para visualizar todas as relações:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorar eventos de arquivos (como criação, modificações e exclusões), fornecendo informações detalhadas sobre esses eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) é uma ferramenta GUI com a aparência e a experiência de uso que os usuários do Windows podem conhecer do _Procmon_ do Microsoft Sysinternals. Essa ferramenta permite iniciar e interromper a gravação de vários tipos de eventos, filtrar esses eventos por categorias como arquivo, processo, rede etc. e salvar os eventos registrados no formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) faz parte das ferramentas de desenvolvimento do Xcode e é usado para monitorar o desempenho de aplicações, identificar memory leaks e acompanhar a atividade do filesystem.

![Crescendo - Apple Instruments: Apple Instruments faz parte das ferramentas de desenvolvimento do Xcode e é usado para monitorar o desempenho de aplicações, identificar memory leaks e acompanhar a atividade do filesystem](<../../../images/image (1138).png>)

### fs_usage

Permite acompanhar as ações executadas pelos processos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele está usando e as conexões de **rede**.\
Ele também verifica os processos do binário no **virustotal** e mostra informações sobre o binário.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Em [**esta publicação do blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) você pode encontrar um exemplo de como fazer **debugging de um daemon em execução** que usava **`PT_DENY_ATTACH`** para impedir o debugging mesmo quando o SIP estava desativado.<sup>[[6]](#references)</sup>

### lldb

**lldb** é a ferramenta de facto para **debugging** de binários do **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Você pode definir o estilo Intel ao usar o lldb criando um arquivo chamado **`.lldbinit`** na sua pasta pessoal com a seguinte linha:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Dentro do lldb, faça o dump de um processo com `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Descrição</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Inicia a execução, que continuará sem interrupção até que um breakpoint seja atingido ou o processo seja encerrado.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia a execução, parando no ponto de entrada</td></tr><tr><td><strong>continue (c)</strong></td><td>Continua a execução do processo em debugging.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Executa a próxima instrução. Esse comando ignora chamadas de funções.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Executa a próxima instrução. Diferentemente do comando nexti, esse comando entra nas chamadas de funções.</td></tr><tr><td><strong>finish (f)</strong></td><td>Executa o restante das instruções na função atual (“frame”), retorna e para.</td></tr><tr><td><strong>control + c</strong></td><td>Pausa a execução. Se o processo tiver sido executado (r) ou continuado (c), isso fará o processo parar ...onde quer que esteja executando no momento.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Exibe a memória como uma string terminada em nulo.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Exibe a memória como uma instrução assembly.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Exibe a memória como um byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Isso exibirá o objeto referenciado pelo parâmetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Observe que a maioria das APIs ou métodos Objective-C da Apple retorna objetos e, portanto, deve ser exibida por meio do comando “print object” (po). Se po não produzir uma saída significativa, use <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Exibe o mapa da memória do processo atual</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Ao chamar a função **`objc_sendMsg`**, o registrador **rsi** contém o **nome do método** como uma string terminada em nulo (“C”). Para exibir o nome via lldb, faça:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Análise Dinâmica

#### Detecção de VM

- O comando **`sysctl hw.model`** retorna "Mac" quando o **host é um MacOS**, mas retorna algo diferente quando está em uma VM.<sup>[[3]](#references)</sup>
- Manipulando os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se estão em uma VM.<sup>[[4]](#references)</sup>
- Alguns malwares também podem **detectar** se a máquina é baseada em **VMware**, com base no endereço MAC (00:50:56).
- Também é possível descobrir **se um processo está sendo depurado** com um código simples, como:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Também é possível invocar a chamada de sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** que um deb**u**gger faça attach e rastreie o processo.
- Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
- Conforme observado neste writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
“_A mensagem Process # exited with **status = 45 (0x0000002d)** geralmente é um sinal claro de que o alvo do debugging está usando **PT_DENY_ATTACH**_”

## Core Dumps

Core dumps são criados se:

- O sysctl `kern.coredump` estiver definido como 1 (por padrão)
- Se o processo não for suid/sgid ou se `kern.sugid_coredump` for 1 (por padrão, é 0)
- O limite `AS_CORE` permitir a operação. É possível impedir a criação de core dumps chamando `ulimit -c 0` e reativá-los com `ulimit -c unlimited`.

Nesses casos, o core dump é gerado de acordo com o sysctl `kern.corefile` e geralmente armazenado em `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

O ReportCrash **analisa processos que sofreram crash e salva um crash report no disco**. Um crash report contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de um crash.\
Para aplicações e outros processos **em execução no contexto per-user do launchd**, o ReportCrash é executado como um LaunchAgent e salva os crash reports em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **em execução no contexto system do launchd** e outros processos privilegiados, o ReportCrash é executado como um LaunchDaemon e salva os crash reports no diretório `/Library/Logs/DiagnosticReports` do sistema.

Se você estiver preocupado com o fato de os crash reports **serem enviados à Apple**, poderá desativá-los. Caso contrário, os crash reports podem ser úteis para **descobrir como um servidor sofreu crash**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Suspensão

Ao fazer fuzzing em um MacOS, é importante não permitir que o Mac entre em suspensão:

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
### Handlers Internos

**Confira a página a seguir** para descobrir como encontrar qual app é responsável por **gerenciar o scheme ou protocolo especificado:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerando Processos de Rede

Isso é interessante para encontrar processos que estão gerenciando dados de rede:
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

Funciona para ferramentas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**"simplesmente funciona"** com ferramentas GUI do macOS. Observe que alguns apps do macOS têm requisitos específicos, como nomes de arquivos exclusivos, a extensão correta e a necessidade de ler os arquivos a partir do sandbox (`~/Library/Containers/com.apple.Safari/Data`)... 

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
### Mais informações sobre Fuzzing no MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referências

- [1] [Resposta a incidentes no OS X: Scripting e análise](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [A arte do malware para Mac, Volume I: análise](https://taomm.org/vol1/analysis.html)
- [4] [A arte do malware para Mac: o guia para análise de software malicioso](https://taomm.org/)
- [5] [knight.sc - informações armazenadas nestas seções desta publicação do blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging de binários da Apple que usam Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Derrotando técnicas Anti-Debug: variantes do ptrace no macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
