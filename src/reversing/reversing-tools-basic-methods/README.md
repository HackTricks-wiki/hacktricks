# Ferramentas de Reversing e Métodos Básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de reversing baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Descompilador de Wasm / compilador de Wat

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binário) para wat (texto legível)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
- você também pode tentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek é um descompilador que **descompila e examina vários formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Depois de descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem aqui é que, se for necessário restaurar um código-fonte perdido a partir de um assembly legado, essa ação pode economizar tempo. Além disso, o dotPeek oferece uma navegação prática pelo código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos do Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-ins e uma API que estende a ferramenta para atender às suas necessidades exatas, o .NET reflector economiza tempo e simplifica o desenvolvimento. Vamos analisar a grande variedade de serviços de engenharia reversa oferecidos por essa ferramenta:

- Fornece uma visão de como os dados fluem por uma biblioteca ou componente
- Fornece uma visão sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para aproveitar melhor as APIs e tecnologias usadas.
- Encontra dependências e diferentes assemblies
- Rastreia a localização exata de erros no seu código, componentes de terceiros e bibliotecas.
- Faz debug no código-fonte de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode usá-lo em qualquer OS (é possível instalá-lo diretamente pelo VSCode, sem precisar baixar o git. Clique em **Extensions** e **pesquise por ILSpy**).\
Se você precisar **descompilar**, **modificar** e **compilar** novamente, pode usar o [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork mantido ativamente dele, o [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modify Method** para alterar algo dentro de uma função).

### Logging do DNSpy

Para fazer o **DNSpy registrar algumas informações em um arquivo**, você pode usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Para depurar código usando DNSpy, você precisa:

Primeiro, alterar os **atributos do Assembly** relacionados à **depuração**:

![Registro do DNSpy - DNSpy Debugging: primeiro, altere os atributos do Assembly relacionados à depuração](<../../images/image (973).png>)

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

Isso é necessário porque, se você não fizer isso, em **runtime** várias **otimizações** serão aplicadas ao código e pode acontecer de um **breakpoint nunca ser atingido** durante a depuração ou de algumas **variáveis não existirem**.

Em seguida, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você poderá **reiniciá-la** com:
```
iisreset /noforce
```
Então, para começar o debugging, você deve fechar todos os arquivos abertos e, dentro da **Debug Tab**, selecionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Então, para começar o debugging, você deve fechar todos os arquivos abertos e, dentro da Debug Tab, selecionar Attach to Process](<../../images/image (318).png>)

Depois, selecione **w3wp.exe** para fazer attach ao **servidor IIS** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Depois, selecione w3wp.exe para fazer attach ao servidor IIS e clique em attach](<../../images/image (113).png>)

Agora que estamos fazendo debugging do processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e depois clique em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Agora que estamos fazendo debugging do processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois clique em Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Agora que estamos fazendo debugging do processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e depois clique em Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Clique em qualquer módulo em Modules e selecione Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Clique com o botão direito em qualquer módulo no Assembly Explorer e clique em Sort Assemblies](<../../images/image (339).png>)

## Descompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging de DLLs

### Usando o IDA

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecione o debugger **Windbg**
- Selecione "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure os **parâmetros** da execução, inserindo o **path para a DLL** e a função que você deseja chamar:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Então, quando você iniciar o debugging, **a execução será interrompida quando cada DLL for carregada**. Quando o rundll32 carregar sua DLL, a execução será interrompida.

Mas como você pode chegar ao código da DLL que foi carregada? Usando este método, não sei como.

### Usando x64dbg/x32dbg

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Altere a Command Line** ( _File --> Change Command Line_ ) e defina o path da dll e a função que você deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Depois, **inicie a execução**. O debugger será interrompido em cada main de dll. Em algum momento, você **será interrompido na dll Entry da sua dll**. A partir daí, basta procurar os pontos onde deseja colocar um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código está** olhando na **parte superior da janela do win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver em qual código está olhando na parte superior da janela do win64dbg](<../../images/image (842).png>)

Então, observando isso, você pode ver quando a execução foi interrompida na dll que deseja debugar.

## Aplicativos GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos dentro da memória de um jogo em execução e alterá-los. Mais informações em:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é um front-end/ferramenta de reverse engineering para o GNU Project Debugger (GDB), com foco em jogos. No entanto, pode ser usado para qualquer atividade relacionada a reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompiladores. Este serviço web permite comparar a saída de diferentes decompiladores em executáveis pequenos.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging de um shellcode com blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **alocará** o **shellcode** dentro de uma região da memória, **indicará** o **endereço de memória** onde o shellcode foi alocado e **interromperá** a execução.\
Depois, você precisa fazer **attach de um debugger** (Ida ou x64dbg) ao processo, inserir um **breakpoint no endereço de memória indicado** e **retomar** a execução. Dessa forma, você estará fazendo debugging do shellcode.

A página de releases do github contém zips com as releases compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging de um shellcode com jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é muito semelhante ao blobrunner. Ele **alocará** o **shellcode** dentro de uma região da memória e iniciará um **loop infinito**. Depois, você precisa fazer **attach do debugger** ao processo, **clicar em start, aguardar de 2 a 5 segundos e pressionar stop**. Você estará dentro do **loop infinito**. Avance para a próxima instrução do loop infinito, pois ela será uma chamada ao shellcode. Por fim, você estará executando o shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it é muito semelhante ao blobrunner. Ele alocará o shellcode dentro de uma região da memória e iniciará um...](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging de shellcode usando o Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como um arquivo, ele o decompilou corretamente, mas quando o abri como shellcode, isso não aconteceu:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Observe que o Cutter permite "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como um arquivo, ele...](<../../images/image (562).png>)

Para iniciar a emulação no local desejado, defina um bp nesse local. Aparentemente, o Cutter iniciará automaticamente a emulação a partir dele:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Para iniciar a emulação no local desejado, defina um bp nesse local. Aparentemente, o Cutter iniciará automaticamente...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Para iniciar a emulação no local desejado, defina um bp nesse local. Aparentemente, o Cutter iniciará automaticamente...](<../../images/image (387).png>)

Você pode ver a stack, por exemplo, dentro de um hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Você pode ver a stack, por exemplo, dentro de um hex dump](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo funções executadas

Você deve experimentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele informará coisas como **quais funções** o shellcode está usando e se o shellcode está **decodificando** a si mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg também conta com um lançador gráfico no qual você pode selecionar as opções desejadas e executar o shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg também conta com um lançador gráfico no qual você pode selecionar as opções desejadas e...](<../../images/image (258).png>)

A opção **Create Dump** fará o dump do shellcode final caso alguma alteração seja feita dinamicamente no shellcode na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para debuggar o shellcode usando o terminal do scDbg (no entanto, considero qualquer uma das opções explicadas anteriormente melhor para isso, pois você poderá usar o Ida ou o x64dbg).

### Disassembling using CyberChef

Faça upload do arquivo de shellcode como entrada e use a seguinte recipe para decompilá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscação de MBA obfuscation

A obfuscation **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples como `x + y` por trás de fórmulas que combinam operações aritméticas (`+`, `-`, `*`) e operadores bitwise (`&`, `|`, `^`, `~`, shifts). A parte importante é que essas identidades geralmente só estão corretas sob **aritmética modular de largura fixa**, portanto carries e overflows são importantes:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, poderá facilmente obter um resultado incorreto, pois a semântica da largura de bits foi ignorada.<sup>[[1]](#references)</sup>

### Fluxo de trabalho prático

1. **Mantenha a largura de bits original** do código/IR/saída do decompiler (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
- **Linear**: somas ponderadas de átomos bitwise
- **Semilinear**: linear mais máscaras constantes, como `x & 0xFF`
- **Polinomial**: há produtos
- **Mista**: produtos e lógica bitwise estão intercalados, geralmente com subexpressões repetidas
3. **Verifique cada reescrita candidata** com testes aleatórios ou uma prova SMT. Se a equivalência não puder ser provada, mantenha a expressão original em vez de fazer suposições.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador prático de MBA para análise de malware e reversing de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados, em vez de aplicar uma única passagem genérica de reescrita a tudo.<sup>[[2]](#references)</sup>

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
- **Semilinear MBA**: átomos mascarados por constantes são reconstruídos com uma reconstrução particionada por bits, mantendo corretas as regiões mascaradas.
- **Polynomial/Mixed MBA**: produtos são decompostos em cores, e subexpressões repetidas podem ser elevadas a temporários antes de simplificar a relação externa.

Exemplo de uma identidade mista que normalmente vale a pena tentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Isso pode ser reduzido a:
```c
x * y
```
### Notas de reversing

- Prefira executar o CoBRA em **expressões de IR levantadas** ou na saída do decompiler após isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética mascarada ou de registradores estreitos.
- Se precisar de uma etapa de prova mais forte, consulte as notas locais sobre Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- O CoBRA também é distribuído como um **plugin de LLVM pass** (`libCobraPass.so`), útil quando você quer normalizar LLVM IR com muito MBA antes de executar passes de análise posteriores.
- Residuais mistos de domínio sensíveis a carry que não são suportados devem ser tratados como um sinal para manter a expressão original e raciocinar manualmente sobre o caminho do carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator **modifica todas as instruções para `mov`** (sim, muito legal). Ele também usa interrupções para alterar os fluxos de execução. Para obter mais informações sobre como funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se você tiver sorte, o [demovfuscator](https://github.com/kirschju/demovfuscator) fará o deobfuscate do binary. Ele tem várias dependências
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, este workaround para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **entry point**, pesquise as funções por `::main`, como em:

![Movfuscator - Rust: Para encontrar o entry point, pesquise as funções por ::main, como em](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bastante óbvio que esta é a função main interessante.\
Tendo o **nome** das **funções** chamadas, pesquise por elas na **Internet** para descobrir suas **entradas** e **saídas**.

### Recuperando strings Rust de firmware ELF

Em binários **Rust ELF**, muitas strings estáticas não são referenciadas como ponteiros terminados em NUL no estilo C. Um layout comum do `rustc` é uma **tupla de ponteiro/comprimento** dentro de **`.data.rel.ro`**, apontando para o blob real da string armazenado em **`.rodata`**:
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
2. Enumere **`.data.rel.ro`** uma word por vez.
3. Trate qualquer valor dentro do intervalo de endereços de `.rodata` como um candidato a ponteiro de string.
4. Trate a próxima word como o comprimento candidato.
5. Aplique filtros de sanidade (por exemplo, mantenha comprimentos entre **4** e **100** bytes).
6. Leia exatamente `length` bytes de `.rodata` em vez de continuar a procurar até `0x00`.

Lógica mínima do extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Isso é especialmente útil na engenharia reversa de firmware, porque as strings Rust recuperadas frequentemente revelam **rotas HTTP, nomes de RPC, mensagens de log, asserções, nomes de arquivos, chaves de configuração, manipuladores de comandos e lógica relacionada à autenticação**.

Se o Ghidra não encontrar essas strings, execute um script/plugin personalizado que aplique a mesma heurística e crie dados de string nos offsets `.rodata` referenciados. As ferramentas `rust-strings` e `RustStrings.py`, publicadas pela Pen Test Partners, são boas referências para adaptar a ideia a outros **tamanhos de palavra, endianness e layouts de seção**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Para binários compilados em Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se precisar fazer engenharia reversa de um binário Delphi, sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta pressionar **ATL+f7** (importar plugin Python no IDA) e selecionar o plugin Python.

Este plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Depois de iniciar a depuração, pressione novamente o botão Start (o verde ou f9), e um breakpoint será atingido no início do código real.

Isso também é muito interessante porque, se você pressionar um botão no aplicativo gráfico, o debugger irá parar na função executada por esse botão.

## Golang

Se precisar fazer engenharia reversa de um binário Golang, sugiro usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta pressionar **ATL+f7** (importar plugin Python no IDA) e selecionar o plugin Python.

Isso resolverá os nomes das funções.

## Compiled Python

Nesta página, você pode encontrar como obter o código Python a partir de um binário ELF/EXE compilado em Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se você obtiver o **binário** de um jogo GBA, poderá usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de debug_) - Contém um debugger com interface
- [**mgba** ](https://mgba.io)- Contém um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** **, você pode ver como pressionar os **botões** do Game Boy Advance

![configuração dos controles do no$gba mostrando os mapeamentos dos botões do Game Boy Advance](<../../images/image (581).png>)

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

Na imagem anterior, você pode ver que a função é chamada a partir de **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

Nessa função, após algumas operações de inicialização (sem nenhuma importância):
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
O último if verifica se **`uVar4`** está nas **últimas Keys** e não é a tecla atual, também chamado de liberar um botão (a tecla atual é armazenada em **`uVar1`**).
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

- Primeiro, ele é comparado com o **valor 4** (botão **SELECT**): no challenge, esse botão limpa a tela
- Em seguida, ele é comparado com o **valor 8** (botão **START**): no challenge, isso verifica se o código é válido para obter a flag.
- Nesse caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for igual, algum código é executado.
- Em todos os outros casos, algum cont (**`DAT_030000d4`**) é verificado. Ele é um cont porque está adicionando 1 logo após entrar no código.\
**S**e for menor que 8, algo que envolve **adicionar** valores a **`DAT_030000d8`** é executado (basicamente, os valores das teclas pressionadas são adicionados a essa variável enquanto o cont for menor que 8).

Portanto, neste challenge, sabendo os valores dos botões, era necessário **pressionar uma combinação com comprimento menor que 8 cujo resultado da soma fosse 0xf3.**

**Referência para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Referências

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
