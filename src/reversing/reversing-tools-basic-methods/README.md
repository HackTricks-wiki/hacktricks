# Ferramentas de engenharia reversa e métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de engenharia reversa baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Depuração do kernel do Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Descompilador Wasm / compilador Wat

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binário) para wat (texto legível)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
- Você também pode experimentar o [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para descompilação.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode em cache do Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Descompilador .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek é um descompilador que **descompila e examina vários formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Depois de descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem é que, se for necessário restaurar um código-fonte perdido a partir de um assembly legado, isso pode economizar tempo. Além disso, dotPeek oferece uma navegação prática pelo código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos do Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-ins e uma API que estende a ferramenta para atender às suas necessidades específicas, o .NET Reflector economiza tempo e simplifica o desenvolvimento. Vamos examinar a variedade de serviços de engenharia reversa que essa ferramenta oferece:

- Revela como os dados fluem por uma biblioteca ou componente
- Revela a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para aproveitar melhor as APIs e tecnologias utilizadas.
- Encontra dependências e diferentes assemblies
- Localiza o ponto exato dos erros no seu código, em componentes de terceiros e em bibliotecas.
- Depura o código-fonte de todo o código .NET com que você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin do ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode usá-lo em qualquer sistema operacional (é possível instalá-lo diretamente pelo VSCode, sem precisar baixar o git. Clique em **Extensions** e **pesquise por ILSpy**).\
Se precisar **descompilar**, **modificar** e **recompilar**, você pode usar o [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork dele mantido ativamente, o [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modify Method** para alterar algo dentro de uma função).

### Registro de logs no DNSpy

Para fazer o **DNSpy registrar algumas informações em um arquivo**, você pode usar este snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuração do DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, altere os **atributos do assembly** relacionados à **depuração**:

![Registro do DNSpy - Depuração do DNSpy: Primeiro, altere os atributos do assembly relacionados à depuração](<../../images/image (973).png>)

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

E clique em **compilar**:

![DNSpy Logging - DNSpy Debugging: E clique em compilar](<../../images/image (314) (1).png>)

Em seguida, salve o novo arquivo em _**Arquivo >> Salvar módulo...**_:

![DNSpy Logging - DNSpy Debugging: Em seguida, salve o novo arquivo em Arquivo Salvar módulo](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, várias **otimizações** serão aplicadas ao código em **tempo de execução**, e pode acontecer que, durante a depuração, um **ponto de interrupção nunca seja atingido** ou algumas **variáveis não existam**.

Então, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:

```
iisreset /noforce
```

Então, para começar a depuração, feche todos os arquivos abertos e, na **Debug Tab**, selecione **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Então, para começar a depuração, feche todos os arquivos abertos e, na Debug Tab, selecione Attach to Process](<../../images/image (318).png>)

Em seguida, selecione **w3wp.exe** para anexar ao **servidor IIS** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Em seguida, selecione w3wp.exe para anexar ao servidor IIS e clique em attach](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e, em seguida, clique em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e, em seguida, clique em Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e, em seguida, clique em Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Clique em qualquer módulo em Modules e selecione Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Clique com o botão direito em qualquer módulo no Assembly Explorer e clique em Sort Assemblies](<../../images/image (339).png>)

## Descompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuração de DLLs

### Usando IDA

- **Carregue rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecione o debugger **Windbg**
- Selecione "**Suspend on library load/unload**"

![Depuração de DLLs - Usando IDA: Selecione " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure os **parâmetros** da execução, informando o **caminho da DLL** e a função que deseja chamar:

![Depuração de DLLs - Usando IDA: Configure os parâmetros da execução, informando o caminho da DLL e a função que deseja chamar](<../../images/image (704).png>)

Então, ao iniciar a depuração, **a execução será interrompida sempre que uma DLL for carregada**. Assim, quando rundll32 carregar sua DLL, a execução será interrompida.

Esse método para nos eventos de carregamento de módulos, mas chegar ao ponto de entrada da DLL carregada é menos direto do que com o fluxo de trabalho do x64dbg abaixo.

### Usando x64dbg/x32dbg

- **Carregue rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Altere a linha de comando** ( _File --> Change Command Line_ ) e defina o caminho da DLL e a função que deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Em seguida, **inicie a execução**. O debugger será interrompido no ponto de entrada de cada DLL e, em algum momento, você **será interrompido no ponto de entrada da sua DLL**. A partir daí, basta procurar os pontos onde deseja definir um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código está** olhando para o **topo da janela do win64dbg**:

![Usando IDA - Usando x64dbg/x32dbg: Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver em qual código está olhando para o topo da janela do win64dbg](<../../images/image (842).png>)

Esse indicador confirma quando a execução foi interrompida dentro da DLL que você quer depurar.

## Aplicativos GUI / videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são armazenados na memória de um jogo em execução e alterá-los. Mais informações em:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta de front-end/engenharia reversa para o GNU Project Debugger (GDB), com foco em jogos. No entanto, pode ser usada para qualquer atividade relacionada à engenharia reversa.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários descompiladores. Esse serviço web permite comparar os resultados de diferentes descompiladores em executáveis pequenos.

## ARM e MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando um shellcode com blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) aloca o **shellcode**, exibe seu **endereço de memória** e pausa a execução.\
Anexe um debugger, como IDA ou x64dbg, defina um breakpoint no endereço exibido e retome a execução para depurar o shellcode.

A página de releases no GitHub contém arquivos ZIP com as versões compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando um shellcode com jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é semelhante ao BlobRunner. Ele aloca o shellcode e entra em um loop infinito. Anexe o debugger, retome a execução por **2–5 segundos**, pause dentro desse loop e avance até a chamada seguinte, que transfere a execução para o shellcode alocado.

![Debugger pausado no loop infinito do jmp2it, imediatamente antes da chamada ao shellcode alocado](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando um shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Com o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite usar "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como arquivo, ele o descompilou corretamente, mas, quando o abri como shellcode, não:

![Cutter exibindo resultados de análise diferentes ao abrir os mesmos bytes como arquivo ou como shellcode](<../../images/image (562).png>)

Para iniciar a emulação no ponto desejado, defina um bp nesse ponto; aparentemente, o Cutter iniciará automaticamente a emulação a partir dele:

![Definindo um breakpoint na entrada desejada do shellcode antes de iniciar a emulação do Cutter](<../../images/image (589).png>)

![Emulador do Cutter pausado no breakpoint selecionado do shellcode](<../../images/image (387).png>)

Você pode ver, por exemplo, a stack em um dump hexadecimal:

![Visualizando a stack do shellcode emulado no dump hexadecimal do Cutter](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo as funções executadas

Você deve experimentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele informa coisas como **quais funções** o shellcode está usando e se o shellcode está **se decodificando** na memória.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

O scDbg também vem com um launcher gráfico, onde você pode selecionar as opções desejadas e executar o shellcode

![Launcher gráfico do scDbg para selecionar opções de emulação e tracing de shellcode](<../../images/image (258).png>)

A opção **Create Dump** gera um dump do shellcode final caso alguma alteração seja feita dinamicamente no shellcode em memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal do scDbg (no entanto, considero qualquer uma das opções explicadas anteriormente melhor para esse fim, pois você poderá usar o Ida ou o x64dbg).

### Desmontagem usando CyberChef

Envie seu arquivo de shellcode como entrada e use a seguinte receita para desmontá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscação de MBA obfuscation

A obfuscation **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples, como `x + y`, por trás de fórmulas que combinam operadores aritméticos (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shifts). O importante é que essas identidades geralmente só são corretas sob **aritmética modular de largura fixa**, portanto, carries e overflows são relevantes:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, poderá facilmente obter um resultado incorreto porque a semântica da largura de bits foi ignorada.<sup>[[1]](#references)</sup>

### Fluxo de trabalho prático

1. **Mantenha a largura de bits original** da saída de código/IR/decompilador levantado (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
   - **Linear**: somas ponderadas de átomos bitwise
   - **Semilinear**: expressão linear mais máscaras constantes, como `x & 0xFF`
   - **Polinomial**: há produtos
   - **Mista**: produtos e lógica bitwise intercalados, geralmente com subexpressões repetidas
3. **Verifique cada reescrita candidata** com testes aleatórios ou uma prova SMT. Se não for possível provar a equivalência, mantenha a expressão original em vez de fazer suposições.

### Contorne o fluxo de controle achatado com uma fatia de execução estreita

Recuperar o grafo de fluxo de controle completo muitas vezes é desnecessário. Com achatamento do fluxo de controle, predicados opacos, grandes dispatchers ou código pesado em MBA, siga as referências dos blobs criptografados e dos buffers de saída até a menor rotina que os transforma. Em seguida, reproduza apenas essa fatia do fluxo de dados ou execute-a de forma independente; o dispatcher não faz parte da solução necessária se o estado relevante puder ser inicializado diretamente.<sup>[[7]](#references)</sup>

Um fluxo de trabalho prático é:<sup>[[7]](#references)</sup>

1. Faça o inventário das seções executáveis e de dados, das relocações e das referências cruzadas. Extraia tabelas candidatas de `.rodata`, preservando a ordem dos bytes e a largura dos elementos.
2. Identifique a última rotina que grava o texto claro ou o buffer de saída. Registre as entradas, as tabelas referenciadas, as chamadas importadas e o estado global necessário.
3. Converta apenas essas operações em um modelo Python de largura fixa. Se a fatia ainda depender de estado demais, invoque a rotina com Unicorn, QEMU ou um debugger e intercepte as importações irrelevantes em vez de emular o programa inteiro.
4. Valide que o extrator realmente deriva sua saída do binário fornecido: remova fallbacks silenciosos, procure respostas embutidas nele e teste-o em builds não vistos, com strings, chaves, identificadores, layouts e seeds de obfuscação diferentes.

Comandos úteis para uma primeira análise:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expressões MBA que ocultam constantes

Uma expressão de byte aparentemente dependente da entrada pode cancelar completamente essa entrada. Depois de extrair suas tabelas, avalie a expressão em todo o domínio de 8 bits; um conjunto de saída unitário prova que esse byte é constante, sem precisar recuperar a máquina de estados ao redor.<sup>[[7]](#references)</sup>

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

Mantenha a máscara final porque a adição original tem wraparound na largura de byte. Para um domínio mais amplo, pergunte a um solver SMT se `f(x1) != f(x2)` é satisfatível para duas entradas simbólicas de mesma largura: `unsat` prova invariância, enquanto `sat` fornece um contraexemplo e significa que a entrada não pode ser descartada.<sup>[[7]](#references)</sup>

#### Reconheça decodificação vinculada ao ambiente

As verificações anti-análise não precisam ramificar nem causar uma falha. Um decoder pode misturar o resultado de um sensor em um bit da chave, em uma constante de opaque predicate ou no estado do flattened dispatcher, continuar normalmente e produzir texto simples plausível, mas falso, em um emulador. Portanto, corrigir apenas os ramos de falha visíveis não é suficiente; rastreie as dependências de dados das sondagens do ambiente até o estado do decoder, compare o mesmo trecho no dispositivo autêntico e no emulador, e teste como forçar o resultado de cada sensor altera o buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador MBA prático para análise de malware e reversing de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados, em vez de aplicar uma única passagem genérica de reescrita a tudo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA avalia a expressão com entradas booleanas, deriva uma assinatura e executa em paralelo vários métodos de recuperação, como correspondência de padrões, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos com máscara constante são reconstruídos com uma reconstrução particionada por bits, para que as regiões mascaradas permaneçam corretas.
- **Polynomial/Mixed MBA**: os produtos são decompostos em núcleos, e subexpressões repetidas podem ser elevadas a temporários antes de simplificar a relação externa.

Exemplo de identidade mista que geralmente vale a pena tentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Isso pode ser reduzido a:

```c
x * y
```

### Notas de engenharia reversa

- Prefira executar CoBRA em **expressões de IR elevadas** ou na saída do decompiler depois de isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética com máscaras ou registradores estreitos.
- Se precisar de uma etapa de prova mais robusta, consulte as notas locais sobre Z3:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA também é distribuído como um **plugin de pass do LLVM** (`libCobraPass.so`), útil quando você quer normalizar IR do LLVM com muito MBA antes de etapas posteriores de análise.
- Resíduos mistos de domínio sensíveis ao carry que não são compatíveis devem ser tratados como um sinal para manter a expressão original e analisar manualmente o caminho do carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator substitui operações do programa por sequências de instruções baseadas em `mov` e usa tratamento de sinais/exceções para alterar o fluxo de controle. Para mais detalhes:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para binários compatíveis, o [demovfuscator](https://github.com/kirschju/demovfuscator) pode desofuscar o resultado. Ele tem várias dependências.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, esta solução alternativa para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **ponto de entrada**, pesquise as funções por `::main`, como em:

![Encontrando um ponto de entrada Rust no Ghidra pesquisando nomes de funções por dois-pontos duplos seguidos de main](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bastante óbvio que essa é a função main interessante.\
Com o **nome** das **funções** chamadas, pesquise por elas na **Internet** para descobrir suas **entradas** e **saídas**.

### Recuperando strings Rust de firmware ELF

Em binários **Rust ELF**, muitas strings estáticas não são referenciadas por ponteiros terminados em NUL no estilo C. Um layout comum do `rustc` é uma **tupla de ponteiro/comprimento** dentro de **`.data.rel.ro`**, apontando para o blob de strings real armazenado em **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Isso significa que `strings` ou a análise padrão do Ghidra podem mesclar strings adjacentes ou deixar de detectar completamente referências cruzadas.<sup>[[3]](#references)</sup>

Fluxo de trabalho rápido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Obtenha o endereço virtual e o tamanho de **`.rodata`**.
2. Enumere **`.data.rel.ro`** uma palavra por vez.
3. Trate qualquer valor dentro do intervalo de endereços de `.rodata` como um possível ponteiro para string.
4. Trate a palavra seguinte como o possível comprimento.
5. Aplique filtros de sanidade (por exemplo, mantenha comprimentos entre **4** e **100** bytes).
6. Leia exatamente `length` bytes de `.rodata` em vez de buscar até `0x00`.

Lógica mínima do extrator:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Isso é especialmente útil em reversing de firmware, pois as strings Rust recuperadas costumam revelar **rotas HTTP, nomes de RPC, mensagens de log, asserções, nomes de arquivos, chaves de configuração, handlers de comandos e lógica relacionada à autenticação**.

Se o Ghidra não encontrar essas strings, execute um script/plugin personalizado que aplique a mesma heurística e crie dados de string nos offsets referenciados de `.rodata`. As ferramentas `rust-strings` e `RustStrings.py`, publicadas pela Pen Test Partners, são boas referências para adaptar a ideia a outros **tamanhos de palavra, endianness e layouts de seção**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binários compilados com Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se precisar fazer reversing de um binário Delphi, recomendo usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Esse plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Depois de iniciar a depuração, pressione novamente o botão Start (o verde ou f9) e um breakpoint será acionado no início do código real.

Se você pressionar um botão no aplicativo gráfico, o debugger poderá parar na função chamada por esse botão.

## Golang

Se precisar fazer reversing de um binário Golang, recomendo usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Isso resolverá os nomes das funções.

## Python compilado

Nesta página, você pode descobrir como obter o código Python de um binário ELF/EXE compilado a partir de Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se você obtiver o **binário** de um jogo de GBA, poderá usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de depuração_) - Inclui um debugger com interface
- [**mgba** ](https://mgba.io)- Inclui um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** **, você pode ver como pressionar os **botões** do Game Boy Advance

![Configuração dos controles do no$gba mostrando o mapeamento dos botões do Game Boy Advance](<../../images/image (581).png>)

Quando pressionada, cada **tecla tem um valor** que a identifica:

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

![Visualização do Ghidra de um binário de GBA referenciando KEYINPUT no endereço 0x4000130](<../../images/image (447).png>)

Na imagem anterior, você pode ver que a função é chamada a partir de **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

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

O último if verifica se **`uVar4`** está nas últimas Keys e não é a tecla atual, o que também é chamado de soltar um botão (a tecla atual é armazenada em **`uVar1`**).

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

- Primeiro, ele é comparado com o **valor 4** (botão **SELECT**): neste desafio, esse botão limpa a tela
- Em seguida, ele compara o valor com **8** (o botão **START**); neste desafio, esse caminho verifica se o código digitado é válido.
  - Nesse caso, a variável **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for igual, um código é executado.
- Em todos os outros casos, um contador (`DAT_030000d4`) é verificado e incrementado.\
  Enquanto o contador estiver abaixo de 8, os valores das teclas pressionadas são acumulados em `DAT_030000d8`.

Então, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com menos de 8 valores cuja soma resultasse em 0xf3.**

**Referência para este tutorial:** [writeup arquivado do desafio Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (desofuscação de binários)

## References

- [1] [Simplificando a ofuscação MBA com CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositório CoBRA da Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificando strings Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing para GBA (arquivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Derrotando o reverse engineering assistido por IA, ou pelo menos tentando](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
