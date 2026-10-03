# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para descobrir onde valores importantes são armazenados na memória de um jogo em execução e alterá-los.\
Quando você o baixa e executa, é apresentado a um **tutorial** sobre como usar a ferramenta. Se quiser aprender a usar a ferramenta, é altamente recomendado concluí-lo.

## O que você está procurando?

![Cheat Engine - O que você está procurando?: O que você está procurando?](<../../images/image (762).png>)

Essa ferramenta é muito útil para descobrir **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente, os números** são armazenados no formato de **4bytes**, mas você também pode encontrá-los nos formatos **double** ou **float**, ou pode querer procurar algo **diferente de um número**. Por esse motivo, você precisa ter certeza de que **selecionou** o que deseja **procurar**:

![Cheat Engine - O que você está procurando?: Geralmente, os números são armazenados no formato de 4bytes, mas você também pode encontrá-los nos formatos double ou float, ou pode querer procurar algo...](<../../images/image (324).png>)

Você também pode indicar **diferentes** tipos de **buscas**:

![Cheat Engine - O que você está procurando?: Você também pode indicar diferentes tipos de buscas](<../../images/image (311).png>)

Você também pode marcar a caixa para **parar o jogo durante a varredura da memória**:

![Cheat Engine - O que você está procurando?: Você também pode marcar a caixa para parar o jogo durante a varredura da memória](<../../images/image (1052).png>)

### Hotkeys

Em _**Edit --> Settings --> Hotkeys**_, você pode definir diferentes **hotkeys** para diferentes finalidades, como **parar** o **jogo** (o que é bastante útil se, em algum momento, você quiser fazer uma varredura da memória). Outras opções estão disponíveis:

![O que você está procurando? - Hotkeys: Em Edit -- Settings -- Hotkeys, você pode definir diferentes hotkeys para diferentes finalidades, como parar o jogo (o que é bastante útil se, em algum momento, você...](<../../images/image (864).png>)

## Modificando o valor

Depois que você **encontrar** onde está o **valor** que está **procurando** (mais informações nas etapas a seguir), você pode **modificá-lo** clicando duas vezes nele e, em seguida, clicando duas vezes no valor:

![Hotkeys - Modificando o valor: Depois que você encontrar onde está o valor que está procurando (mais informações nas etapas a seguir), você pode modificá-lo clicando duas vezes nele e, em seguida, clicando duas vezes...](<../../images/image (563).png>)

E, por fim, **marcando a caixa** para que a modificação seja feita na memória:

![Hotkeys - Modificando o valor: E, por fim, marcando a caixa para que a modificação seja feita na memória](<../../images/image (385).png>)

A **alteração** na **memória** será **aplicada** imediatamente (observe que, até que o jogo use esse valor novamente, o valor **não será atualizado no jogo**).

## Procurando o valor

Vamos supor que exista um valor importante (como a vida do seu usuário) que você queira aumentar e que esteja procurando esse valor na memória.

### Por meio de uma alteração conhecida

Supondo que você esteja procurando o valor 100, você **realiza uma varredura** procurando esse valor e encontra muitas ocorrências:

![Procurando o valor - Por meio de uma alteração conhecida: Supondo que você esteja procurando o valor 100, você realiza uma varredura procurando esse valor e encontra muitas ocorrências](<../../images/image (108).png>)

Em seguida, você faz algo para que o **valor mude**, **para** o jogo e **realiza** uma **nova varredura**:

![Procurando o valor - Por meio de uma alteração conhecida: Em seguida, você faz algo para que o valor mude, para o jogo e realiza uma nova varredura](<../../images/image (684).png>)

O Cheat Engine procurará os **valores** que **passaram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando e agora pode modificá-lo.\
_Se ainda houver vários valores, faça algo para modificar esse valor novamente e realize outra "nova varredura" para filtrar os endereços._

### Valor desconhecido, alteração conhecida

No cenário em que você **não conhece o valor**, mas sabe **como fazê-lo mudar** (e até mesmo o valor da alteração), você pode procurar esse número.

Comece realizando uma varredura do tipo "**Unknown initial value**":

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Comece realizando uma varredura do tipo " Unknown initial value "](<../../images/image (890).png>)

Em seguida, faça o valor mudar, indique **como** o **valor** **mudou** (no meu caso, ele diminuiu em 1) e realize uma **nova varredura**:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Em seguida, faça o valor mudar, indique como o valor mudou (no meu caso, ele diminuiu em 1) e realize uma nova varredura](<../../images/image (371).png>)

Serão apresentados **todos os valores que foram modificados da maneira selecionada**:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Serão apresentados todos os valores que foram modificados da maneira selecionada](<../../images/image (569).png>)

Depois que encontrar seu valor, você poderá modificá-lo.

Observe que há **muitas alterações possíveis** e você pode executar essas **etapas quantas vezes quiser** para filtrar os resultados:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Observe que há muitas alterações possíveis e você pode executar essas etapas quantas vezes quiser para filtrar os resultados](<../../images/image (574).png>)

### Endereço de memória aleatório - Encontrando o código

Até agora, aprendemos a encontrar um endereço que armazena um valor, mas é muito provável que, em **execuções diferentes do jogo, esse endereço esteja em locais diferentes da memória**. Portanto, vamos descobrir como sempre encontrar esse endereço.

Usando alguns dos truques mencionados, encontre o endereço onde o jogo atual está armazenando o valor importante. Em seguida (parando o jogo, se desejar), clique com o **botão direito** no **endereço** encontrado e selecione "**Find out what accesses this address**" ou "**Find out what writes to this address**":

![Valor desconhecido, alteração conhecida - Endereço de memória aleatório - Encontrando o código: Usando alguns dos truques mencionados, encontre o endereço onde o jogo atual está armazenando o valor importante. Em seguida...](<../../images/image (1067).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** esse **endereço** (o que é útil para outras coisas, como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica** e será mais útil neste caso, pois estamos interessados em saber **de onde esse valor está sendo escrito**.

Depois que você selecionar uma dessas opções, o **debugger** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deverá ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![Valor desconhecido, alteração conhecida - Endereço de memória aleatório - Encontrando o código: Depois que você selecionar uma dessas opções, o debugger será anexado ao programa e uma nova janela vazia...](<../../images/image (91).png>)

Agora que você encontrou o endereço que modifica o valor, pode **modificar o código como quiser** (o Cheat Engine permite modificá-lo rapidamente para NOPs):

![Valor desconhecido, alteração conhecida - Endereço de memória aleatório - Encontrando o código: Agora que você encontrou o endereço que modifica o valor, pode modificar o código como quiser (o Cheat Engine...](<../../images/image (1057).png>)

Assim, você pode modificá-lo para que o código não afete seu número ou sempre o afete de maneira positiva.

### Endereço de memória aleatório - Encontrando o ponteiro

Seguindo as etapas anteriores, encontre onde está o valor no qual você está interessado. Em seguida, usando "**Find out what writes to this address**", descubra qual endereço escreve esse valor e clique duas vezes nele para obter a visualização da disassembly:

![Endereço de memória aleatório - Encontrando o código - Endereço de memória aleatório - Encontrando o ponteiro: Seguindo as etapas anteriores, encontre onde está o valor no qual você está interessado. Em seguida, usando " Find out...](<../../images/image (1039).png>)

Depois, realize uma nova varredura **procurando o valor hexadecimal entre "\[]"** (o valor de $edx neste caso):

![Endereço de memória aleatório - Encontrando o código - Endereço de memória aleatório - Encontrando o ponteiro: Depois, realize uma nova varredura procurando o valor hexadecimal entre " ()" (o valor de $edx neste caso)](<../../images/image (994).png>)

(_Se aparecerem vários, geralmente você precisa do que possui o menor endereço_)\
Agora, **encontramos o ponteiro que modificará o valor no qual estamos interessados**.

Clique em "**Add Address Manually**":

![Endereço de memória aleatório - Encontrando o código - Endereço de memória aleatório - Encontrando o ponteiro: Clique em " Add Address Manually "](<../../images/image (990).png>)

Agora, clique na caixa de seleção "Pointer" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior era "Tutorial-i386.exe"+2426B0):

![Endereço de memória aleatório - Encontrando o código - Endereço de memória aleatório - Encontrando o ponteiro: Agora, clique na caixa de seleção "Pointer" e adicione o endereço encontrado na caixa de texto (neste cenário,...](<../../images/image (392).png>)

(Observe como o primeiro "Address" é preenchido automaticamente com o endereço do ponteiro que você inseriu)

Clique em OK e um novo ponteiro será criado:

![Endereço de memória aleatório - Encontrando o código - Endereço de memória aleatório - Encontrando o ponteiro: Clique em OK e um novo ponteiro será criado](<../../images/image (308).png>)

Agora, sempre que você modificar esse valor, estará **modificando o valor importante, mesmo que o endereço de memória onde o valor está seja diferente.**

### Code Injection

Code injection é uma técnica na qual você injeta um trecho de código no processo-alvo e, em seguida, redireciona a execução do código para passar pelo código escrito por você (como receber pontos em vez de perdê-los).

Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador:

![Endereço de memória aleatório - Encontrando o ponteiro - Code Injection: Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador](<../../images/image (203).png>)

Clique em Show disassembler para obter o **código disassemblado**.\
Em seguida, clique em **CTRL+a** para abrir a janela Auto assemble e selecione _**Template --> Code Injection**_

![Endereço de memória aleatório - Encontrando o ponteiro - Code Injection: Em seguida, clique em CTRL+a para abrir a janela Auto assemble e selecione Template -- Code Injection](<../../images/image (902).png>)

Preencha o **endereço da instrução que deseja modificar** (isso geralmente é preenchido automaticamente):

![Endereço de memória aleatório - Encontrando o ponteiro - Code Injection: Preencha o endereço da instrução que deseja modificar (isso geralmente é preenchido automaticamente)](<../../images/image (744).png>)

Um template será gerado:

![Endereço de memória aleatório - Encontrando o ponteiro - Code Injection: Um template será gerado](<../../images/image (944).png>)

Agora, insira seu novo código assembly na seção "**newmem**" e remova o código original de "**originalcode**" se não quiser que ele seja executado**.** Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![Endereço de memória aleatório - Encontrando o ponteiro - Code Injection: Agora, insira seu novo código assembly na seção " newmem " e remova o código original de " originalcode " se não...](<../../images/image (521).png>)

**Clique em execute e assim por diante, e seu código deverá ser injetado no programa, alterando o comportamento da funcionalidade!**

## Code Injection seguro contra relocação com assinaturas AOB

Um script que faz hook em `game.exe+123456` pode deixar de funcionar após o ASLR ou uma atualização de software. Uma **assinatura Array of Bytes (AOB)** encontra a instrução a partir do código de máquina ao seu redor. Use `aobscanmodule` para restringir a busca a um módulo. Faça a assinatura ser longa o suficiente para retornar uma única correspondência. Use wildcards nos bytes de relocação, endereços e outros bytes que possam mudar. Não use wildcards na instrução inteira que você precisa restaurar.<sup>[[4]](#references)</sup>

Na Memory View, selecione a instrução e use **Tools → Auto Assemble → Template → AOB Injection**. O bloco `[DISABLE]` gerado é importante. Ele deve restaurar todos os bytes sobrescritos e liberar a alocação.<sup>[[4]](#references)</sup>

<details>
<summary>Esqueleto mínimo de AOB injection para x64</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Antes de ativar o script, verifique estes pontos:

1. O AOB retorna **um** endereço. Adicione instruções estáveis em ambos os lados se ele retornar mais de um.
2. O jump substitui instruções completas. Nunca divida uma instrução.
3. A cave alocada pode ser alcançada pelo jump gerado. Em x64, uma alocação distante pode precisar de um jump de 14 bytes.
4. O código injetado preserva os registradores, flags e o alinhamento da stack esperados pela função original.
5. O bloco de disable restaura os bytes originais exatos. Teste enable e disable várias vezes antes de salvar a tabela.

## Fluxo de trabalho confiável para ponteiros

Um ponteiro encontrado em uma execução é apenas um candidato. Crie pointer maps em várias execuções novas e faça o rescan usando todas elas. Reinicie o target entre as capturas para que o ASLR e as alocações de heap mudem. Prefira caminhos cuja base seja um módulo ou outro símbolo estável. Rejeite caminhos que funcionem apenas com um save, level ou uma instância específica do objeto.

O filtro **the pointer must end with specific offsets** e sua opção de deviation podem manter caminhos úteis quando um campo próximo muda entre builds. A release 7.5 também adicionou esse controle de deviation. Ele é um filtro, não uma prova de que uma pointer chain é estável.<sup>[[1]](#references)</sup>

Quando uma estrutura muda com frequência demais para o pointer scanning, faça hook na instrução que a acessa. Capture o ponteiro do objeto ativo a partir de um registrador para um símbolo alocado. Isso costuma ser mais confiável para entity lists e managed objects.

## Rastreando código em vez de escanear valores

Use **Find out what writes to this address** quando o valor é modificado diretamente. Use **Find out what accesses this address** quando precisar do objeto proprietário ou quando a escrita ocorrer por meio de dados copiados. Acione apenas uma ação no target. Em seguida, compare a quantidade de ocorrências e o estado dos registradores.

**Ultimap 2** usa Intel Processor Trace em CPUs Intel compatíveis. Ele registra o control flow executado com menos interrupções do que executar cada instrução passo a passo. Filtre o código executado enquanto a ação relevante ocorria e remova o código que também foi executado durante uma captura em idle. Intel PT não é um recurso de stealth. O target ainda pode detectar o tracing, alterações de timing ou o próprio Cheat Engine.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 também adicionou uma interface Intel PT fornecida pelo Windows. O modo Ultimap mais antigo, baseado em DBVM, e o modo Intel PT têm requisitos diferentes de hardware e sistema operacional. Não presuma que uma CPU compatível com DBVM ofereça suporte a Intel PT.<sup>[[1]](#references)</sup>

## Seleção de debugger e breakpoint

Escolha o debugger menos invasivo que funcione:

- **Windows debugger** é simples, mas cria eventos de debug normais. Verificações de anti-debugging podem detectá-lo.
- **VEH debugger** trata breakpoints por meio de um vectored exception handler. Ele evita algumas verificações básicas de debugger, mas não é invisível.
- **Hardware breakpoints** não alteram os bytes da instrução, mas x86/x64 fornece apenas uma pequena quantidade de slots de debug-register.
- **Software breakpoints** substituem um byte por `INT3`. São fáceis de detectar e podem entrar em conflito com verificações de integridade.
- **DBVM debugger** move algumas operações para abaixo do guest OS. Ele tem muito mais privilégios e pode travar o host se estiver configurado incorretamente.

Cheat Engine 7.5 pode usar um jump de um byte baseado em um exception handler e `INT3` quando não houver espaço suficiente para um relative jump normal. Trate-o como um software breakpoint. Verifique o fluxo de exceção e não presuma que ele contorne verificações de anti-tamper.<sup>[[1]](#references)</sup>

DBVM é um hypervisor, não um switch geral de invisibilidade. Use-o apenas em um lab descartável. Não exponha sua control interface a código não confiável. Produtos de kernel anti-cheat e endpoint ainda podem detectar o driver, o estado do hypervisor ou a memória modificada.

## Managed runtimes e recursos recentes do 7.6/7.7

Para targets Mono, IL2CPP, .NET e Java, prefira metadata do runtime em vez de scans cegos quando disponível. Abra **Mono → Activate mono features** ou a janela correspondente de informações do runtime. Localize primeiro a class, field ou method. Em seguida, use a disassembly nativa quando o managed method for compilado por JIT.

A linha 7.6 adicionou `AOBSCANEX` para signatures somente em memória executável, uma interface de debugger `gdbserver`, inspeção de Java metadata, enumeração IL2CPP mais rápida e uma opção de pointer-scan que ignora o byte superior do ponteiro usado pelo ARM memory tagging. A linha 7.7 adicionou builds nativos para Linux, `HOOK`/`UNHOOK`, `aobscanfunction`, uma busca aprimorada de generic Mono methods, suporte melhorado a estruturas PDB e dissection básica de estruturas da Unreal Engine.<sup>[[3]](#references)</sup>

Essas adições permitem um fluxo de trabalho útil:

1. Resolva um managed method ou static field a partir dos metadata.
2. Faça trace ou disassembly do código nativo produzido para esse method.
3. Use `AOBSCANEX` ou `aobscanfunction` para localizar uma executable signature estável.
4. Gere um hook reversível. Mantenha as instruções originais e valide o caminho de disable.
5. Verifique novamente a signature após cada update do target. Um match bem-sucedido não garante que a lógica ao redor ainda tenha o mesmo significado.

## Targets remotos com `ceserver`

`ceserver` expõe enumeração de processos, acesso à memória e debugging para a GUI do Cheat Engine. Os builds oficiais abrangem Linux e Android. Execute a arquitetura correspondente no target e conecte-se pela aba **Network**. No Android, fazer forwarding da porta padrão evita expô-la na rede:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
A bridge de terceiros `frida-ceserver` pode fornecer uma interface compatível com o Cheat Engine para alvos iOS. Ela não é o `ceserver` oficial, e as operações suportadas podem ser diferentes.<sup>[[2]](#references)</sup>

Assuma que o protocolo concede acesso em nível de debugger. Faça o bind em loopback ou coloque-o atrás de um túnel SSH/ADB. Nunca exponha a porta TCP 52736 a uma rede não confiável. Pare o servidor quando a sessão terminar.

## Segurança operacional

Anexe-se somente a software que seja seu ou que você esteja autorizado a testar. Não execute o Cheat Engine ao lado de um jogo online ou endpoint de produção. Escritas na memória, código injetado, drivers e DBVM podem travar ou corromper o alvo.<sup>[[3]](#references)</sup>

Baixe builds do site oficial ou compile o código-fonte publicado. Produtos de segurança frequentemente classificam editores de memória, debuggers e seus drivers como ferramentas de hacking. Não desative globalmente a proteção do host. Use uma VM dedicada ou um host de laboratório e verifique o artefato antes de executá-lo.<sup>[[3]](#references)</sup>



## References

- [1] [Notas de lançamento do Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge frida-ceserver para alvos remotos](https://github.com/gmh5225/frida-ceserver)
- [3] [Notícias oficiais de lançamento do Cheat Engine](https://www.cheatengine.org/)
- [4] [Wiki do Cheat Engine: AOBs do Auto Assembler](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
