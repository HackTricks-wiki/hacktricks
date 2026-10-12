# Ferramentas de reversing e métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de reversing baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Depuração do kernel do Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Descompilador de Wasm / compilador de Wat

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

## Payloads virtualizados e VMs personalizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

O dotPeek é um descompilador que **descompila e examina vários formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Depois de descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem é que, se for necessário restaurar um código-fonte perdido a partir de um assembly legado, isso pode economizar tempo. Além disso, o dotPeek oferece uma navegação prática pelo código descompilado, o que o torna uma das ferramentas perfeitas para **análise de algoritmos do Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-ins e uma API que estende a ferramenta para atender exatamente às suas necessidades, o .NET Reflector economiza tempo e simplifica o desenvolvimento. Vamos conhecer a variedade de serviços de engenharia reversa que essa ferramenta oferece:

- Mostra como os dados fluem por uma biblioteca ou componente
- Mostra detalhes sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para aproveitar melhor as APIs e tecnologias utilizadas.
- Encontra dependências e diferentes assemblies
- Localiza o ponto exato dos erros no seu código, em componentes de terceiros e em bibliotecas.
- Depura o código-fonte de todo o código .NET com que você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin do ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): você pode usá-lo em qualquer sistema operacional (é possível instalá-lo diretamente pelo VSCode; não é necessário baixar o git. Clique em **Extensions** e **pesquise por ILSpy**).\
Se precisar **descompilar**, **modificar** e **recompilar**, você pode usar o [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork mantido ativamente, o [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modify Method** para alterar algo dentro de uma função).

### Logging do DNSpy

Para fazer o **DNSpy registrar algumas informações em um arquivo**, você pode usar este trecho:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuração com DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, altere os **atributos do Assembly** relacionados à **depuração**:

![Registro do DNSpy - Depuração com DNSpy: Primeiro, altere os atributos do Assembly relacionados à depuração](<../../images/image (973).png>)

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

Em seguida, salve o novo arquivo usando _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Em seguida, salve o novo arquivo usando File Save module](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, várias **optimisations** serão aplicadas ao código em **runtime**, e é possível que, durante a depuração, um **break-point nunca seja atingido** ou algumas **variáveis não existam**.

Em seguida, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:

```
iisreset /noforce
```

Então, para começar a depurar, feche todos os arquivos abertos e, na **Debug Tab**, selecione **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Então, para começar a depurar, feche todos os arquivos abertos e, na Debug Tab, selecione Attach to Process](<../../images/image (318).png>)

Em seguida, selecione **w3wp.exe** para se conectar ao **servidor IIS** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Em seguida, selecione w3wp.exe para se conectar ao servidor IIS e clique em attach](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e depois em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois em Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois em Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Clique em qualquer módulo em Modules e selecione Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Clique com o botão direito em qualquer módulo no Assembly Explorer e clique em Sort Assemblies](<../../images/image (339).png>)

## Decompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depurando DLLs

### Usando IDA

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecione o depurador **Windbg**
- Selecione "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecione " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure os **parâmetros** da execução, informando o **caminho da DLL** e a função que você quer chamar:

![Debugging DLLs - Using IDA: Configure os parâmetros da execução, informando o caminho da DLL e a função que você quer chamar](<../../images/image (704).png>)

Então, ao iniciar a depuração, **a execução será interrompida sempre que uma DLL for carregada**. Assim, quando o rundll32 carregar sua DLL, a execução será interrompida.

Esse método interrompe a execução em eventos de carregamento de módulos, mas chegar ao ponto de entrada da DLL carregada é menos direto do que no fluxo de trabalho do x64dbg apresentado abaixo.

### Usando x64dbg/x32dbg

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Altere a linha de comando** ( _File --> Change Command Line_ ) e informe o caminho da DLL e a função que você quer chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Em seguida, **inicie a execução**. O depurador será interrompido no ponto de entrada de cada DLL e, em algum momento, você **parará no ponto de entrada da sua DLL**. A partir daí, basta procurar os locais onde quer definir um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código está** olhando na **parte superior da janela do win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver em qual código está olhando na parte superior da janela do win64dbg](<../../images/image (842).png>)

Esse indicador confirma quando a execução é interrompida dentro da DLL que você quer depurar.

## Aplicativos GUI / videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos na memória de um jogo em execução e alterá-los. Mais informações em:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta front-end/de engenharia reversa para o GNU Project Debugger (GDB), com foco em jogos. No entanto, pode ser usada para qualquer atividade relacionada à engenharia reversa.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompiladores. Esse serviço web permite comparar a saída de diferentes decompiladores em executáveis pequenos.

## ARM e MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando um shellcode com blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) aloca o **shellcode**, exibe seu **endereço de memória** e pausa a execução.\
Conecte um depurador, como IDA ou x64dbg, defina um breakpoint no endereço exibido e retome a execução para depurar o shellcode.

A página de releases do GitHub contém arquivos ZIP com as versões compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando um shellcode com jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é semelhante ao BlobRunner. Ele aloca o shellcode e entra em um loop infinito. Conecte o depurador, retome a execução por **2–5 segundos**, pause dentro desse loop e avance até a chamada seguinte, que transfere a execução para o shellcode alocado.

![Depurador pausado no loop infinito do jmp2it, imediatamente antes da chamada para o shellcode alocado](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a interface gráfica do radare. Usando o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite usar "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como arquivo, ele foi descompilado corretamente, mas, quando o abri como shellcode, isso não aconteceu:

![Cutter mostrando resultados de análise diferentes ao abrir os mesmos bytes como arquivo ou como shellcode](<../../images/image (562).png>)

Para iniciar a emulação no local desejado, defina um bp nesse ponto e, aparentemente, o Cutter iniciará a emulação automaticamente a partir dali:

![Definindo um breakpoint na entrada desejada do shellcode antes de iniciar a emulação do Cutter](<../../images/image (589).png>)

![Emulador do Cutter pausado no breakpoint selecionado do shellcode](<../../images/image (387).png>)

Você pode, por exemplo, ver a stack em um dump hexadecimal:

![Visualização da stack do shellcode emulado no dump hexadecimal do Cutter](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo as funções executadas

Você pode experimentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele informa, por exemplo, **quais funções** o shellcode está usando e se o shellcode está **se decodificando** na memória.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg também conta com um launcher gráfico, onde você pode selecionar as opções desejadas e executar o shellcode

![Launcher gráfico do scDbg para selecionar opções de emulação e tracing de shellcode](<../../images/image (258).png>)

A opção **Create Dump** fará o dump do shellcode final se alguma alteração for feita dinamicamente no shellcode na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para fazer debug do shellcode usando o terminal do scDbg (no entanto, considero melhores para isso as opções explicadas anteriormente, pois você poderá usar o Ida ou o x64dbg).

### Desassemblar usando CyberChef

Carregue o arquivo do shellcode como entrada e use a seguinte receita para desassemblá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscação de MBA obfuscation

A obfuscation **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples, como `x + y`, por trás de fórmulas que combinam operadores aritméticos (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shifts). O ponto importante é que essas identidades geralmente só são corretas sob **aritmética modular de largura fixa**, então os carries e overflows importam:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, pode facilmente obter um resultado incorreto porque a semântica da largura em bits foi ignorada.<sup>[[1]](#references)</sup>

### Fluxo de trabalho prático

1. **Mantenha a largura em bits original** da saída de código/IR/decompilador levantada (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
   - **Linear**: somas ponderadas de átomos bit a bit
   - **Semilinear**: linear mais máscaras constantes, como `x & 0xFF`
   - **Polinomial**: há produtos
   - **Mista**: produtos e lógica bit a bit intercalados, geralmente com subexpressões repetidas
3. **Verifique cada reescrita candidata** com testes aleatórios ou uma prova SMT. Se não for possível provar a equivalência, mantenha a expressão original em vez de tentar adivinhar.

### Contorne o fluxo de controle achatado com uma fatia de execução estreita

Recuperar o grafo completo de fluxo de controle muitas vezes é desnecessário. Com control-flow flattening, predicados opacos, grandes dispatchers ou código com muito MBA, siga as referências de blobs criptografados e buffers de saída até a menor rotina que os transforma. Em seguida, reproduza apenas essa fatia do fluxo de dados ou execute-a de forma independente; o dispatcher não faz parte da solução necessária se o estado relevante puder ser inicializado diretamente.<sup>[[7]](#references)</sup>

Um fluxo de trabalho prático é:<sup>[[7]](#references)</sup>

1. Faça um inventário das seções executáveis e de dados, das relocações e das referências cruzadas. Extraia tabelas candidatas de `.rodata`, preservando a ordem dos bytes e a largura dos elementos.
2. Identifique a última rotina que grava o texto claro ou o buffer de saída. Registre suas entradas, tabelas referenciadas, chamadas importadas e o estado global necessário.
3. Transponha apenas essas operações para um modelo Python de largura fixa. Se a fatia ainda depender de estado demais, invoque a rotina com Unicorn, QEMU ou um debugger e intercepte as importações irrelevantes em vez de emular o programa inteiro.
4. Valide se o extrator realmente deriva sua saída do binário fornecido: remova fallbacks silenciosos, procure respostas embutidas nele e execute-o em builds não vistos, com strings, chaves, identificadores, layouts e sementes de ofuscação diferentes.

Comandos úteis para uma primeira análise:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expressões MBA que são constantes disfarçadas

Uma expressão de byte aparentemente dependente da entrada pode cancelar completamente essa entrada. Depois de extrair suas tabelas, avalie a expressão em todo o domínio de 8 bits; um conjunto de saída unitário prova que esse byte é constante, sem recuperar a máquina de estados ao redor.<sup>[[7]](#references)</sup>

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

Mantenha a máscara final porque a soma original tem wraparound na largura de byte. Para um domínio mais amplo, pergunte a um solver SMT se `f(x1) != f(x2)` é satisfatível para duas entradas simbólicas da mesma largura: `unsat` prova invariância, enquanto `sat` fornece um contraexemplo e significa que a entrada não pode ser descartada.<sup>[[7]](#references)</sup>

#### Reconhecer decodificação vinculada ao ambiente

As verificações anti-análise não precisam causar desvios de fluxo ou falhas. Um decodificador pode misturar o resultado de um sensor em um bit da chave, em uma constante de predicado opaco ou no estado de um dispatcher achatado, continuar normalmente e produzir texto simples plausível, mas falso, em um emulador. Portanto, corrigir apenas os desvios de falha visíveis não é suficiente; rastreie as dependências de dados das sondagens do ambiente até o estado do decodificador, compare o mesmo trecho no dispositivo autêntico e no emulador e teste como forçar cada resultado do sensor altera o buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador de MBA prático para análise de malware e engenharia reversa de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados, em vez de aplicar uma única passagem genérica de reescrita a tudo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA avalia a expressão com entradas booleanas, deriva uma assinatura e executa em paralelo vários métodos de recuperação, como pattern matching, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos mascarados por constantes são reconstruídos com uma reconstrução particionada por bits, para que as regiões mascaradas permaneçam corretas.
- **Polynomial/Mixed MBA**: os produtos são decompostos em núcleos, e subexpressões repetidas podem ser extraídas para temporários antes de simplificar a relação externa.

Exemplo de uma identidade mista que geralmente vale a pena tentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Isso pode ser reduzido a:

```c
x * y
```

### Notas sobre reversing

- Prefira executar CoBRA em **expressões de IR lifted** ou na saída do decompilador depois de isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética com máscaras ou registradores estreitos.
- Se precisar de uma etapa de prova mais robusta, consulte as notas locais sobre Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA também vem como um **plugin pass do LLVM** (`libCobraPass.so`), útil quando você quer normalizar IR do LLVM com muito MBA antes de etapas posteriores de análise.
- Resíduos mistos de domínios sensíveis a carry que não sejam suportados devem ser tratados como um sinal para manter a expressão original e analisar manualmente o caminho do carry.

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

Se você estiver jogando um **CTF, este workaround para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **ponto de entrada**, pesquise as funções por `::main`, como em:

![Encontrando um ponto de entrada Rust no Ghidra pesquisando nomes de funções por dois-pontos duplos e main](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bastante óbvio que esta é a função main interessante.\
Tendo o **nome** das **funções** chamadas, pesquise por elas na **Internet** para descobrir suas **entradas** e **saídas**.

### Recuperando strings Rust de firmware ELF

Em binários **ELF Rust**, muitas strings estáticas não são referenciadas como ponteiros terminados em NUL no estilo C. Um layout comum de `rustc` é uma **tupla de ponteiro/comprimento** dentro de **`.data.rel.ro`** apontando para o blob de string real armazenado em **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Isso significa que `strings` ou a análise padrão do Ghidra podem mesclar strings adjacentes ou deixar de identificar referências cruzadas.<sup>[[3]](#references)</sup>

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
6. Leia exatamente `length` bytes de `.rodata` em vez de procurar até `0x00`.

Lógica mínima do extrator:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Isso é especialmente útil no reversing de firmware porque as strings Rust recuperadas geralmente revelam **rotas HTTP, nomes de RPC, mensagens de log, assertions, nomes de arquivo, chaves de configuração, handlers de comando e lógica relacionada à autenticação**.

Se o Ghidra não encontrar essas strings, execute um script/plugin personalizado que aplique a mesma heurística e crie dados de string nos offsets referenciados em `.rodata`. As ferramentas `rust-strings` e `RustStrings.py`, publicadas pela Pen Test Partners, são boas referências para adaptar a ideia a outros **tamanhos de palavra, endianness e layouts de seção**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binários compilados com Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se precisar fazer reversing de um binário Delphi, sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pressione **Alt+F7** no IDA para carregar um plugin Python e selecione o arquivo do plugin.

Esse plugin executa o binário e resolve os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Start (o verde ou f9), e um breakpoint será atingido no início do código real.

Se você pressionar um botão no aplicativo gráfico, o debugger poderá parar na função invocada por esse botão.

## Golang

Para binários Go comuns, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) pode recuperar estruturas de runtime e melhorar os nomes das funções no IDA. Carregue o plugin Python com **Alt+F7**.

### Recuperar metadados sem a tabela de símbolos

Um executável Go stripped ainda precisa de metadados de runtime para mapear program counters para funções. [GoReSym](https://github.com/mandiant/GoReSym) localiza e analisa estruturas como `pclntab` e `moduledata` usando código derivado do runtime do Go. Isso pode recuperar limites de função, nomes, caminhos de origem, tipos e detalhes do build sem depender da tabela de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Um obfuscator pode deixar essas estruturas utilizáveis enquanto substitui os nomes recuperados. O Garble, por exemplo, aplica hash a identificadores e caminhos de pacotes e remove informações de build, módulo e depuração.<sup>[[12]](#references)</sup> O token ofuscado do pacote deve permanecer consistente entre as funções desse pacote. Agrupe as funções pelo token repetido, infira um pacote a partir das funções chamadas, strings e APIs e, em seguida, propague o rótulo desse pacote para todo o grupo.<sup>[[13]](#references)</sup>

### Recupere nomes do Garble com GoResolver

O [GoResolver](https://github.com/volexity/GoResolver) combina a extração de símbolos em runtime com a geração de referências limpas e a correspondência de grafos de fluxo de controle (CFG). Use esta sequência:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifique a versão do compilador.** Primeiro, tente usar `BuildInfo` e strings de versão incorporadas. Se o obfuscator as tiver removido, compare partes do runtime Go incluído com runtimes de referência versionados. Nos testes da Volexity, cerca de `2%` do runtime bastou para distinguir as principais versões do Go. Considere isso uma otimização empírica, não um limite universal.<sup>[[13]](#references)</sup>
2. **Crie referências correspondentes.** Gere binários limpos para a versão identificada do Go, a arquitetura de destino e as bibliotecas prováveis. Corresponder a toolchain reduz as diferenças nos CFGs geradas pelo compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compare as funções.** O GoGrapher corresponde CFGs de funções e emite pontuações normalizadas de `0.0` a `1.0`. A correspondência de blocos básicos se baseia em uma comparação ponderada de instruções semelhantes. Correspondências com alto nível de confiança mapeiam funções com nomes aleatorizados para a implementação limpa. Correspondências mais fracas ainda podem identificar um pacote ou módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valide e importe.** Confirme os nomes propostos usando relações entre chamadas, constantes, strings e efeitos colaterais; em seguida, importe o relatório JSON com o plugin do GoResolver para IDA ou Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instale a toolchain e execute o extrator combinado com o comparador de grafos:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

O limiar padrão de correspondência significativa é `0.9`. As opções `--extract` e `--graph` podem isolar cada etapa, enquanto a execução padrão realiza ambas, pois os metadados de runtime recuperados e as evidências do CFG se complementam.<sup>[[10]](#references)</sup> As pontuações do CFG são heurísticas: inlining, flags de build, arquitetura e diferenças entre versões de bibliotecas podem alterar a estrutura do grafo; portanto, mantenha as funções não resolvidas em vez de atribuir nomes com baixa confiança.<sup>[[13]](#references)</sup>

## Python compilado

Nesta página, você pode encontrar como obter o código Python de um binário ELF/EXE compilado em Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se você obtiver o **binário** de um jogo de GBA, poderá usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de depuração_) - Inclui um depurador com interface
- [**mgba** ](https://mgba.io)- Inclui um depurador CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** **, você pode ver como pressionar os **botões** do Game Boy Advance

![configuração dos controles do no$gba mostrando o mapeamento dos botões do Game Boy Advance](<../../images/image (581).png>)

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

![Visualização do Ghidra de um binário GBA que faz referência a KEYINPUT no endereço 0x4000130](<../../images/image (447).png>)

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

Este código foi encontrado:

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

O último if verifica se **`uVar4`** está nas últimas teclas e não é a tecla atual, também conhecido como soltar um botão (a tecla atual é armazenada em **`uVar1`**).

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

- Primeiro, ele é comparado com o **valor 4** (botão **SELECT**): neste desafio, esse botão limpa a tela.
- Em seguida, o valor é comparado com **8** (o botão **START**); neste desafio, esse caminho verifica se o código inserido é válido.
  - Nesse caso, a variável **`DAT_030000d8`** é comparada com 0xf3 e, se os valores forem iguais, algum código é executado.
- Em qualquer outro caso, um contador (`DAT_030000d4`) é verificado e incrementado.\
  Enquanto o contador estiver abaixo de 8, os valores das teclas pressionadas são acumulados em `DAT_030000d8`.

Portanto, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com menos de 8 teclas cujo resultado da soma fosse 0xf3.**

**Referência para este tutorial:** [artigo arquivado sobre o desafio Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscação de binários)

## References

- [1] [Simplificando a obfuscation MBA com CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositório CoBRA da Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificando strings Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - strings Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (arquivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Derrotando a engenharia reversa assistida por IA, ou pelo menos tentando](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Uma abordagem para comparar grafos de fluxo de controle baseada na correspondência de blocos básicos](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mecanismo de obfuscation do Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: usando similaridade de grafos de fluxo de controle para desofuscar automaticamente binários Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
