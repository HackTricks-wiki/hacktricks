# Ferramentas de Reversing e Métodos Básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de Reversing baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binário) para wat (texto claro)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
- Você também pode experimentar o [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para decompilação.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

O dotPeek é um decompiler que **decompila e examina vários formatos**, incluindo **biblioteca**s (.dll), **arquivo**s de metadados do Windows (.winmd) e **executáveis** (.exe). Depois de decompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem aqui é que, se for necessário restaurar um código-fonte perdido a partir de um assembly legado, essa ação pode economizar tempo. Além disso, o dotPeek fornece uma navegação conveniente pelo código decompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos do Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-ins e uma API que estende a ferramenta para atender às suas necessidades exatas, o .NET Reflector economiza tempo e simplifica o desenvolvimento. Vamos examinar a grande quantidade de serviços de reverse engineering fornecidos por essa ferramenta:

- Fornece uma visão de como os dados fluem por uma biblioteca ou componente
- Fornece informações sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para aproveitar melhor as APIs e tecnologias utilizadas.
- Encontra dependências e diferentes assemblies
- Localiza a posição exata dos erros no seu código, componentes de terceiros e bibliotecas.
- Faz debug no código-fonte de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode tê-lo em qualquer sistema operacional (pode instalá-lo diretamente pelo VSCode, sem necessidade de baixar o git. Clique em **Extensions** e **pesquise por ILSpy**).\
Se você precisar **decompilar**, **modificar** e **compilar novamente**, pode usar o [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork mantido ativamente, o [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modify Method** para alterar algo dentro de uma função).

### DNSpy Logging

Para fazer com que o **DNSpy registre algumas informações em um arquivo**, você pode usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuração do DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, alterar os **atributos do Assembly** relacionados à **depuração**:

![DNSpy Logging - Depuração do DNSpy: Primeiro, altere os atributos do Assembly relacionados à depuração](<../../images/image (973).png>)

De:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Para:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
E clique em **compile**:

![DNSpy Logging - DNSpy Debugging: E clique em compile](<../../images/image (314) (1).png>)

Em seguida, salve o novo arquivo por meio de _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Em seguida, salve o novo arquivo por meio de File Save module](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, em **runtime** várias **otimizações** serão aplicadas ao código e pode acontecer de, durante a depuração, um **break-point nunca ser atingido** ou algumas **variáveis não existirem**.

Em seguida, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você poderá **reiniciá-la** com:
```
iisreset /noforce
```
Então, para começar a depuração, você deve fechar todos os arquivos abertos e, dentro da **Debug Tab**, selecionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Então, para começar a depuração, você deve fechar todos os arquivos abertos e, dentro da Debug Tab, selecionar Attach to Process](<../../images/image (318).png>)

Em seguida, selecione **w3wp.exe** para anexá-lo ao **IIS server** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Em seguida, selecione w3wp.exe para anexá-lo ao IIS server e clique em attach](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e depois em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois em Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois em Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Clique em qualquer módulo em Modules e selecione Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Clique com o botão direito em qualquer módulo no Assembly Explorer e clique em Sort Assemblies](<../../images/image (339).png>)

## Descompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depurando DLLs

### Usando IDA

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecione o debugger **Windbg**
- Selecione "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecione " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure os **parameters** da execução inserindo o **path para a DLL** e a função que você deseja chamar:

![Debugging DLLs - Using IDA: Configure os parameters da execução inserindo o path para a DLL e a função que você deseja chamar](<../../images/image (704).png>)

Então, quando você iniciar a depuração, **a execução será interrompida sempre que cada DLL for carregada**; assim, quando o rundll32 carregar sua DLL, a execução será interrompida.

Esse método interrompe a execução em eventos de carregamento de módulo, mas alcançar o entry point da DLL carregada é menos direto do que no workflow do x64dbg abaixo.

### Usando x64dbg/x32dbg

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Altere a Command Line** ( _File --> Change Command Line_ ) e defina o path da dll e a função que você deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Em seguida, **inicie a execução**; o debugger será interrompido em cada dll main e, em algum momento, você **parará no dll Entry da sua dll**. A partir daí, basta procurar os pontos onde deseja inserir um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código está** observando a **parte superior da janela do win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver em qual código está observando a parte superior da janela do win64dbg](<../../images/image (842).png>)

Esse indicador confirma quando a execução foi interrompida dentro da DLL que você deseja depurar.

## Aplicativos GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são armazenados dentro da memória de um jogo em execução e alterá-los. Mais informações em:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta de front-end/reverse engineering para o GNU Project Debugger (GDB), com foco em jogos. No entanto, ela pode ser usada para qualquer atividade relacionada a reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompiladores. Esse serviço web permite comparar a saída de diferentes decompiladores em executáveis pequenos.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando um shellcode com blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) aloca o **shellcode**, imprime seu **memory address** e pausa a execução.\
Anexe um debugger, como o IDA ou o x64dbg, defina um breakpoint no endereço impresso e retome a execução para depurar o shellcode.

A página de github das releases contém zips com as releases compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando um shellcode com jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é semelhante ao BlobRunner. Ele aloca o shellcode e entra em um loop infinito. Anexe o debugger, retome a execução por **2–5 segundos**, pause dentro desse loop e avance até a chamada seguinte que transfere a execução para o shellcode alocado.

![Debugger pausado no loop infinito do jmp2it imediatamente antes da chamada para o shellcode alocado](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como um arquivo, ele foi descompilado corretamente, mas quando o abri como shellcode, isso não aconteceu:

![Cutter mostrando resultados de análise diferentes ao abrir os mesmos bytes como arquivo ou como shellcode](<../../images/image (562).png>)

Para iniciar a emulação no local desejado, defina um bp nesse local e, aparentemente, o Cutter iniciará automaticamente a emulação a partir dele:

![Definindo um breakpoint no entry point desejado do shellcode antes de iniciar a emulação do Cutter](<../../images/image (589).png>)

![Emulador do Cutter pausado no breakpoint selecionado do shellcode](<../../images/image (387).png>)

Você pode ver a stack, por exemplo, dentro de um hex dump:

![Visualizando a stack do shellcode emulado no hex dump do Cutter](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo funções executadas

Você deve tentar usar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele informará coisas como **quais funções** o shellcode está usando e se o shellcode está **decodificando** a si mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
O scDbg também conta com um launcher gráfico no qual você pode selecionar as opções desejadas e executar o shellcode

![Launcher gráfico do scDbg para selecionar opções de emulação e tracing do shellcode](<../../images/image (258).png>)

A opção **Create Dump** fará o dump do shellcode final caso alguma alteração seja feita dinamicamente no shellcode em memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para debugar o shellcode usando o terminal do scDbg (no entanto, considero qualquer uma das opções explicadas anteriormente melhor para isso, pois será possível usar o Ida ou o x64dbg).

### Disassembling using CyberChef

Faça upload do seu arquivo de shellcode como entrada e use a seguinte recipe para desmontá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscação de obfuscação MBA

A obfuscação **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples como `x + y` atrás de fórmulas que combinam operações aritméticas (`+`, `-`, `*`) e operadores bitwise (`&`, `|`, `^`, `~`, shifts). A parte importante é que essas identidades geralmente só são corretas sob **aritmética modular de largura fixa**, portanto carries e overflows importam:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, poderá facilmente obter um resultado incorreto, porque a semântica da largura dos bits foi ignorada.<sup>[[1]](#references)</sup>

### Fluxo de trabalho prático

1. **Mantenha a largura de bits original** do código/IR/saída do decompiler (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
- **Linear**: somas ponderadas de átomos bitwise
- **Semilinear**: linear mais máscaras constantes, como `x & 0xFF`
- **Polinomial**: há produtos
- **Mista**: produtos e lógica bitwise estão intercalados, geralmente com subexpressões repetidas
3. **Verifique toda reescrita candidata** com testes aleatórios ou uma prova SMT. Se a equivalência não puder ser provada, mantenha a expressão original em vez de fazer suposições.

### Ignore o control-flow flattening com um narrow execution slice

Recuperar o grafo de fluxo de controle completo geralmente é desnecessário. Com control-flow flattening, opaque predicates, dispatchers grandes ou código com muito MBA, siga as referências a partir de blobs criptografados e buffers de saída até a menor rotina que os transforma. Em seguida, reproduza apenas esse data-flow slice ou execute-o de forma independente; o dispatcher não faz parte da solução necessária se o estado relevante puder ser inicializado diretamente.<sup>[[7]](#references)</sup>

Um fluxo de trabalho prático é:<sup>[[7]](#references)</sup>

1. Faça um inventário das seções executáveis e de dados, relocations e referências cruzadas. Extraia tabelas candidatas de `.rodata`, preservando a ordem dos bytes e a largura dos elementos.
2. Identifique a última rotina que grava o plaintext ou o buffer de saída. Registre suas entradas, tabelas referenciadas, chamadas importadas e estado global necessário.
3. Transponha apenas essas operações para um modelo Python de largura fixa. Se o slice ainda depender de estado demais, invoque a rotina com Unicorn, QEMU ou um debugger e intercepte imports irrelevantes em vez de emular o programa inteiro.
4. Valide se o extractor realmente deriva sua saída do binário fornecido: remova fallbacks silenciosos, procure respostas incorporadas nele e execute-o contra builds não vistos com strings, chaves, identificadores, layouts e seeds de obfuscação diferentes.

Comandos úteis para uma primeira análise são:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Detecte expressões MBA que são constantes disfarçadas

Uma expressão de bytes aparentemente dependente da entrada pode cancelar completamente sua entrada. Depois de extrair suas tabelas, avalie a expressão em todo o domínio de 8 bits; um conjunto de saída unitário prova que esse byte é constante sem recuperar a máquina de estados circundante.<sup>[[7]](#references)</sup>
```python
def mba(a, b, c, d, e, x):
return ((((a | (~x & 0xff)) & c) +
((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
outputs = {mba(*row, x) for x in range(256)}
if len(outputs) != 1:
raise ValueError("expression depends on x")
decoded.append(outputs.pop())
print(decoded)
```
Mantenha a máscara final, pois a adição original tem wraparound na largura do byte. Para um domínio mais amplo, pergunte a um SMT solver se `f(x1) != f(x2)` é satisfatível para duas entradas simbólicas com a mesma largura: `unsat` prova a invariância, enquanto `sat` fornece um contraexemplo e significa que a entrada não pode ser descartada.<sup>[[7]](#references)</sup>

#### Reconheça decodificação vinculada ao ambiente

As verificações anti-análise não precisam causar desvios ou travamentos. Um decoder pode misturar o resultado de um sensor em um bit da chave, em uma constante de predicado opaco ou no estado de um dispatcher flattenizado, continuar normalmente e produzir plaintext plausível, porém falso, em um emulador. Portanto, aplicar patch apenas nos branches visíveis de falha é insuficiente; rastreie as dependências de dados das sondas do ambiente até o estado do decoder, compare o mesmo trecho no dispositivo autêntico e no emulador e teste como forçar cada resultado do sensor altera o buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador prático de MBA para análise de malware e reversing de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados, em vez de aplicar uma única etapa genérica de reescrita a tudo.<sup>[[2]](#references)</sup>

Uso rápido:
```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```
Casos úteis:

- **Linear MBA**: o CoBRA avalia a expressão em entradas booleanas, deriva uma assinatura e executa em paralelo vários métodos de recuperação, como pattern matching, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos mascarados por constantes são reconstruídos com reconstrução particionada em bits, mantendo corretas as regiões mascaradas.
- **Polynomial/Mixed MBA**: produtos são decompostos em cores, e subexpressões repetidas podem ser transformadas em temporários antes de simplificar a relação externa.

Exemplo de uma identidade mista que geralmente vale a pena tentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Isso pode ser reduzido a:
```c
x * y
```
### Notas de reversing

- Prefira executar o CoBRA em **expressões de IR lifted** ou na saída do decompiler após isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética com máscaras ou registradores estreitos.
- Se precisar de uma etapa de prova mais forte, consulte as notas locais do Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- O CoBRA também é distribuído como um **plugin de pass do LLVM** (`libCobraPass.so`), útil quando você quer normalizar LLVM IR com muito MBA antes de outras passagens de análise.
- Residuais mistos sensíveis a carry que não são suportados devem ser tratados como um sinal para manter a expressão original e analisar manualmente o caminho do carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator substitui operações do programa por sequências de instruções baseadas em `mov` e usa tratamento de sinais/exceções para alterar o fluxo de controle. Para obter detalhes:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para binários compatíveis, o [demovfuscator](https://github.com/kirschju/demovfuscator) pode deobfuscate o resultado. Ele tem várias dependências.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, esta técnica para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **entry point**, pesquise as funções por `::main`, como em:

![Encontrando um entry point de Rust no Ghidra pesquisando nomes de funções por main com dois-pontos duplos](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bastante óbvio que esta é a função main interessante.\
Sabendo o **nome** das **funções** chamadas, pesquise por elas na **Internet** para aprender sobre suas **entradas** e **saídas**.

### Recuperando strings de Rust a partir de firmware ELF

Em binários **Rust ELF**, muitas strings estáticas não são referenciadas como ponteiros terminados em NUL no estilo C. Um layout comum do `rustc` é uma **tupla de ponteiro/comprimento** dentro de **`.data.rel.ro`**, apontando para o blob de string real armazenado em **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Isso significa que `strings` ou a análise padrão do Ghidra podem mesclar strings adjacentes ou não encontrar referências cruzadas completamente.<sup>[[3]](#references)</sup>

Fluxo de trabalho rápido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtenha o endereço virtual e o tamanho de **`.rodata`**.
2. Enumere **`.data.rel.ro`** uma palavra por vez.
3. Trate qualquer valor dentro do intervalo de endereços de `.rodata` como um ponteiro candidato para uma string.
4. Trate a palavra seguinte como o comprimento candidato.
5. Aplique filtros de sanidade (por exemplo, mantenha comprimentos entre **4** e **100** bytes).
6. Leia exatamente `length` bytes de `.rodata` em vez de continuar a leitura até `0x00`.

Lógica mínima do extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Isso é especialmente útil na engenharia reversa de firmware, porque as strings Rust recuperadas geralmente revelam **rotas HTTP, nomes de RPC, mensagens de log, asserções, nomes de arquivos, chaves de configuração, handlers de comandos e lógica relacionada à autenticação**.

Se o Ghidra não encontrar essas strings, execute um script/plugin personalizado que aplique a mesma heurística e crie dados de string nos offsets `.rodata` referenciados. As ferramentas `rust-strings` e `RustStrings.py`, publicadas pela Pen Test Partners, são boas referências para adaptar a ideia a outros **tamanhos de palavra, endianness e layouts de seção**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binários compilados em Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se precisar fazer engenharia reversa de um binário Delphi, sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Esse plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Start (o verde ou f9), e um breakpoint será atingido no início do código real.

Se você pressionar um botão no aplicativo gráfico, o debugger poderá parar na função invocada por esse botão.

## Golang

Se precisar fazer engenharia reversa de um binário Golang, sugiro usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Isso resolverá os nomes das funções.

## Python compilado

Nesta página, você pode encontrar como obter o código Python a partir de um binário ELF/EXE compilado em Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se você obtiver o **binário** de um jogo de GBA, poderá usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de debug_) - Contém um debugger com interface
- [**mgba** ](https://mgba.io)- Contém um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** ** você pode ver como pressionar os **botões** do Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Quando pressionada, cada **tecla tem um valor** para identificá-la:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Então, nesse tipo de programa, a parte interessante será **como o programa trata a entrada do usuário**. No endereço **0x4000130**, você encontrará a função comumente encontrada: **KEYINPUT**.

![Visualização do Ghidra de um binário GBA referenciando KEYINPUT no endereço 0x4000130](<../../images/image (447).png>)

Na imagem anterior, você pode ver que a função é chamada por **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

Nessa função, após algumas operações de inicialização (sem importância):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Foi encontrado este código:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
O último if verifica se **`uVar4`** está nas **Keys** finais e não é a chave atual, também chamado de liberar um botão (a chave atual é armazenada em **`uVar1`**).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
No código anterior, você pode ver que estamos comparando **uVar1** (o local onde está o **valor do botão pressionado**) com alguns valores:

- Primeiro, ele é comparado com o **valor 4** (botão **SELECT**): no desafio, esse botão limpa a tela
- Em seguida, ele compara o valor com **8** (botão **START**); neste desafio, esse caminho verifica se o código inserido é válido.
- Nesse caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for igual, algum código é executado.
- Em todos os outros casos, um contador (`DAT_030000d4`) é verificado e incrementado.\
Enquanto o contador for menor que 8, os valores das teclas pressionadas são acumulados em `DAT_030000d8`.

Portanto, neste desafio, sabendo os valores dos botões, era necessário **pressionar uma combinação com comprimento menor que 8 cuja soma resultante fosse 0xf3.**

**Referência para este tutorial:** [writeup arquivado do desafio Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuscação de binários)

## References

- [1] [Simplificando a obfuscação MBA com CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositório CoBRA da Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificando strings Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (arquivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Derrotando o reverse engineering assistido por IA, ou pelo menos tentando](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
