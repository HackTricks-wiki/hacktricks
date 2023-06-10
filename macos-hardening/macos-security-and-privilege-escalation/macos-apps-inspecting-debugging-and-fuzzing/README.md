# macOS Apps - Inspeção, depuração e Fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Análise estática

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

O comando `objdump` é uma ferramenta de linha de comando que permite inspecionar arquivos binários e executáveis. Ele pode ser usado para visualizar informações sobre seções, símbolos, relocs e outras informações úteis. O `objdump` é uma ferramenta útil para analisar binários e executáveis em busca de vulnerabilidades e outras informações importantes.
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
```
### jtool2

A ferramenta pode ser usada como um **substituto** para **codesign**, **otool** e **objdump**, e fornece algumas funcionalidades adicionais.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

```
### Codesign

Codesign é uma ferramenta de linha de comando que permite assinar digitalmente aplicativos e arquivos no macOS. A assinatura digital é usada para verificar a integridade e autenticidade do aplicativo ou arquivo. Isso é importante para garantir que o aplicativo ou arquivo não tenha sido modificado ou corrompido por terceiros mal-intencionados. A assinatura digital também é usada para permitir que o aplicativo ou arquivo seja executado em sistemas macOS com Gatekeeper habilitado.
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
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) é uma ferramenta útil para inspecionar arquivos **.pkg** (instaladores) e ver o que está dentro antes de instalá-los. Esses instaladores possuem scripts bash `preinstall` e `postinstall` que os autores de malware geralmente abusam para **persistir** o **malware**.

### hdiutil

Esta ferramenta permite **montar** imagens de disco Apple (**.dmg**) para inspecioná-las antes de executar qualquer coisa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Será montado em `/Volumes`

### Objective-C

Quando uma função é chamada em um binário que usa Objective-C, o código compilado, em vez de chamar essa função, chamará **`objc_msgSend`**. Que chamará a função final:

![](<../../../.gitbook/assets/image (560).png>)

Os parâmetros que essa função espera são:

* O primeiro parâmetro (**self**) é "um ponteiro que aponta para a **instância da classe que receberá a mensagem**". Ou, de forma mais simples, é o objeto no qual o método está sendo invocado. Se o método for um método de classe, isso será uma instância do objeto da classe (como um todo), enquanto para um método de instância, o self apontará para uma instância instanciada da classe como um objeto.
* O segundo parâmetro (**op**) é "o seletor do método que manipula a mensagem". Novamente, de forma mais simples, este é apenas o **nome do método**.
* Os parâmetros restantes são quaisquer **valores necessários pelo método** (op).

| **Argumento**      | **Registro**                                                    | **(para) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1º argumento**  | **rdi**                                                         | **self: objeto no qual o método está sendo invocado** |
| **2º argumento**  | **rsi**                                                         | **op: nome do método**                                 |
| **3º argumento**  | **rdx**                                                         | **1º argumento para o método**                         |
| **4º argumento**  | **rcx**                                                         | **2º argumento para o método**                         |
| **5º argumento**  | **r8**                                                          | **3º argumento para o método**                         |
| **6º argumento**  | **r9**                                                          | **4º argumento para o método**                         |
| **7º+ argumento** | <p><strong>rsp+</strong><br><strong>(na pilha)</strong></p> | **5º+ argumento para o método**                        |

### Binários compactados

* Verifique a alta entropia
* Verifique as strings (se houver quase nenhuma string compreensível, compactada)
* O empacotador UPX para MacOS gera uma seção chamada "\_\_XHDR"

## Análise dinâmica

{% hint style="warning" %}
Observe que, para depurar binários, **o SIP precisa ser desativado** (`csrutil disable` ou `csrutil enable --without debug`) ou copiar os binários para uma pasta temporária e **remover a assinatura** com `codesign --remove-signature <binary-path>` ou permitir a depuração do binário (você pode usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Observe que, para **instrumentar binários do sistema**, (como `cloudconfigurationd`) no macOS, **o SIP deve ser desativado** (apenas remover a assinatura não funcionará).
{% endhint %}

### Hopper

#### Painel esquerdo

No painel esquerdo do Hopper, é possível ver os símbolos (**Labels**) do binário, a lista de procedimentos e funções (**Proc**) e as strings (**Str**). Essas não são todas as strings, mas as definidas em várias partes do arquivo Mac-O (como _cstring ou_ `objc_methname`).

#### Painel central

No painel central, você pode ver o **código desmontado**. E você pode vê-lo como uma desmontagem **bruta**, como **gráfico**, como **descompilado** e como **binário** clicando no ícone respectivo:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Clicando com o botão direito em um objeto de código, você pode ver **referências para/de esse objeto** ou até mesmo mudar seu nome (isso não funciona no pseudocódigo descompilado):

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Além disso, no **meio inferior, você pode escrever comandos python**.

#### Painel direito

No painel direito, você pode ver informações interessantes, como o **histórico de navegação** (para saber como você chegou à situação atual), o **gráfico de chamadas** onde você pode ver todas as **funções que chamam essa função** e todas as funções que **essa função chama**, e informações de **variáveis locais**.

### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Você pode usar este mesmo com o **SIP ativado**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### dtrace

Ele permite que os usuários acessem aplicativos em um nível extremamente **baixo** e fornece uma maneira para os usuários **rastrearem** **programas** e até mesmo mudarem seu fluxo de execução. O Dtrace usa **sondas** que são **colocadas em todo o kernel** e estão em locais como o início e o fim das chamadas do sistema.

O DTrace usa a função **`dtrace_probe_create`** para criar uma sonda para cada chamada do sistema. Essas sondas podem ser disparadas no **ponto de entrada e saída de cada chamada do sistema**. A interação com o DTrace ocorre por meio do /dev/dtrace, que está disponível apenas para o usuário root.

As sondas disponíveis do dtrace podem ser obtidas com:
```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```
O nome da sonda consiste em quatro partes: o provedor, o módulo, a função e o nome (`fbt:mach_kernel:ptrace:entry`). Se você não especificar alguma parte do nome, o Dtrace aplicará essa parte como um caractere curinga.

Para configurar o DTrace para ativar sondas e especificar quais ações executar quando elas são acionadas, precisaremos usar a linguagem D.

Uma explicação mais detalhada e mais exemplos podem ser encontrados em [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemplos

Execute `man -k dtrace` para listar os **scripts DTrace disponíveis**. Exemplo: `sudo dtruss -n binary`

* Em linha
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* script
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
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) é uma ferramenta muito útil para verificar as ações relacionadas a processos que um processo está executando (por exemplo, monitorar quais novos processos um processo está criando).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorar eventos de arquivos (como criação, modificações e exclusões), fornecendo informações detalhadas sobre esses eventos.

### fs\_usage

Permite acompanhar as ações executadas pelos processos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) é útil para ver as **bibliotecas** usadas por um binário, os **arquivos** que ele está usando e as **conexões de rede**.\
Ele também verifica os processos binários no **virustotal** e mostra informações sobre o binário.

### lldb

**lldb** é a ferramenta **de facto** para **depuração** de binários **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
| **Comando (lldb)**            | **Descrição**                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Inicia a execução, que continuará sem interrupção até que um ponto de interrupção seja atingido ou o processo seja encerrado.                                                                                                                                                                                                                                                                                                                     |
| **continue (c)**              | Continua a execução do processo depurado.                                                                                                                                                                                                                                                                                                                                                                               |
| **nexti (n / ni)**            | Executa a próxima instrução. Este comando irá pular chamadas de função.                                                                                                                                                                                                                                                                                                                                                 |
| **stepi (s / si)**            | Executa a próxima instrução. Ao contrário do comando nexti, este comando irá entrar nas chamadas de função.                                                                                                                                                                                                                                                                                                                       |
| **finish (f)**                | Executa o restante das instruções na função atual ("frame"), retorna e para.                                                                                                                                                                                                                                                                                                                                   |
| **control + c**               | Pausa a execução. Se o processo foi executado (r) ou continuado (c), isso fará com que o processo pare... onde quer que esteja executando no momento.                                                                                                                                                                                                                                                                             |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Lista de pontos de interrupção</p><p>br e/dis &#x3C;num> #Ativar/Desativar ponto de interrupção</p><p>breakpoint delete &#x3C;num><br>b set -n main --shlib &#x3C;lib_name></p>                                                                                                                                                                               |
| **help**                      | <p>help breakpoint #Obter ajuda do comando de ponto de interrupção</p><p>help memory write #Obter ajuda para escrever na memória</p>                                                                                                                                                                                                                                                                                                         |
| **reg**                       | <p>reg read</p><p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                      |
| **x/s \<reg/memory address>** | Exibe a memória como uma string terminada em nulo.                                                                                                                                                                                                                                                                                                                                                                           |
| **x/i \<reg/memory address>** | Exibe a memória como instrução de montagem.                                                                                                                                                                                                                                                                                                                                                                               |
| **x/b \<reg/memory address>** | Exibe a memória como byte.                                                                                                                                                                                                                                                                                                                                                                                               |
| **print object (po)**         | <p>Isso irá imprimir o objeto referenciado pelo parâmetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Observe que a maioria das APIs ou métodos Objective-C da Apple retornam objetos e, portanto, devem ser exibidos por meio do comando "print object" (po). Se po não produzir uma saída significativa, use <code>x/b</code></p> |
| **memory**                    | <p>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escreve AAAA nesse endereço<br>memory write -f s $rip+0x11f+7 "AAAA" #Escreve AAAA no endereço</p>                                                                                                                                                                                                                            |
| **disassembly**               | <p>dis #Desmonta a função atual<br>dis -c 6 #Desmonta 6 linhas<br>dis -c 0x100003764 -e 0x100003768 #De um endereço até o outro<br>dis -p -c 4 #Começa no endereço atual desmontando</p>                                                                                                                                                                                                                                 |
| **parray**                    | parray 3 (char \*\*)$x1 #Verifica o array de 3 componentes no registro x1                                                                                                                                                                                                                                                                                                                                                           |

{% hint style="info" %}
Ao chamar a função **`objc_sendMsg`**, o registro **rsi** contém o **nome do método** como uma string terminada em nulo ("C"). Para imprimir o nome via lldb, faça:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análise Dinâmica

#### Detecção de VM

* O comando **`sysctl hw.model`** retorna "Mac" quando o **host é um MacOS**, mas algo diferente quando é uma VM.
* Manipulando os valores de **`hw.logicalcpu`** e **`hw.physicalcpu`**, alguns malwares tentam detectar se é uma VM.
* Alguns malwares também podem **detectar** se a máquina é baseada no VMware pelo endereço MAC (00:50:56).
* Também é possível encontrar **se um processo está sendo depurado** com um código simples como:

  * `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processo sendo depurado }`

* Ele também pode invocar a chamada do sistema **`ptrace`** com a flag **`PT_DENY_ATTACH`**. Isso **impede** um depurador de anexar e rastrear.
  * Você pode verificar se a função **`sysctl`** ou **`ptrace`** está sendo **importada** (mas o malware pode importá-la dinamicamente)
  * Como observado neste artigo, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
    "_A mensagem Process # exited with **status = 45 (0x0000002d)** é geralmente um sinal revelador de que o alvo de depuração está usando **PT\_DENY\_ATTACH**_"

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analisa processos que falharam e salva um relatório de falha no disco**. Um relatório de falha contém informações que podem **ajudar um desenvolvedor a diagnosticar** a causa de uma falha.\
Para aplicativos e outros processos **executados no contexto do launchd por usuário**, o ReportCrash é executado como um LaunchAgent e salva relatórios de falhas em `~/Library/Logs/DiagnosticReports/` do usuário.\
Para daemons, outros processos **executados no contexto do launchd do sistema** e outros processos privilegiados, o ReportCrash é executado como um LaunchDaemon e salva relatórios de falhas em `/Library/Logs/DiagnosticReports` do sistema.

Se você está preocupado com os relatórios de falhas **sendo enviados para a Apple**, você pode desativá-los. Caso contrário, os relatórios de falhas podem ser úteis para **descobrir como um servidor falhou**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Dormir

Ao fazer fuzzing em um MacOS, é importante não permitir que o Mac durma:

* systemsetup -setsleep Never
* pmset, Preferências do Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexão SSH

Se você estiver fazendo fuzzing por meio de uma conexão SSH, é importante garantir que a sessão não vá expirar. Portanto, altere o arquivo sshd\_config com:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manipuladores Internos

**Confira a seguinte página** para descobrir como você pode encontrar qual aplicativo é responsável por **manipular o esquema ou protocolo especificado:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumerando Processos de Rede

Isso é interessante para encontrar processos que estão gerenciando dados de rede:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ou use `netstat` ou `lsof`

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para ferramentas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Ele "**simplesmente funciona"** com ferramentas GUI do macOS. Observe que alguns aplicativos do macOS têm requisitos específicos, como nomes de arquivos exclusivos, a extensão correta, precisam ler os arquivos do sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Alguns exemplos:

{% code overflow="wrap" %}
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

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referências

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
