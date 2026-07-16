# Ferramentas de Reversing & Métodos Básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de Reversing baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Descompilador Wasm / Compilador Wat

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binário) para wat (texto claro)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
- você também pode tentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Descompilador .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek é um descompilador que **descompila e examina múltiplos formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Depois de descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

O mérito aqui é que, se um código-fonte perdido precisar ser restaurado a partir de um assembly legadо, essa ação pode economizar tempo. Além disso, o dotPeek fornece navegação útil por todo o código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmo Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-in e uma API que estende a ferramenta para atender exatamente às suas necessidades, o .NET reflector economiza tempo e simplifica o desenvolvimento. Vamos dar uma olhada na grande variedade de serviços de engenharia reversa que esta ferramenta oferece:

- Fornece uma visão de como os dados fluem por uma biblioteca ou componente
- Fornece visão sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para obter mais das APIs e tecnologias usadas.
- Encontra dependências e diferentes assemblies
- Localiza a posição exata de erros no seu código, componentes de terceiros e bibliotecas.
- Faz debug na origem de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin do ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode tê-lo em qualquer SO (você pode instalá-lo diretamente pelo VSCode, não há necessidade de baixar o git. Clique em **Extensions** e **search ILSpy**).\
Se você precisar **descompilar**, **modificar** e **recompilar** novamente, você pode usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork mantido ativamente dele, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** para mudar algo dentro de uma função).

### Registro de logs no DNSpy

Para fazer o **DNSpy registrar algumas informações em um arquivo**, você pode usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Para depurar código usando DNSpy, você precisa:

Primeiro, altere os **Assembly attributes** relacionados a **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Depois salve o novo arquivo via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, em **runtime** várias **optimisations** serão aplicadas ao código e pode ser que, ao depurar, um **break-point is never hit** ou algumas **variables don't exist**.

Então, se sua aplicação .NET estiver sendo **run** por **IIS**, você pode **restart** ela com:
```
iisreset /noforce
```
Then, para começar a depurar, você deve fechar todos os arquivos abertos e, dentro da **Debug Tab**, selecionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Depois, selecione **w3wp.exe** para anexar ao **IIS server** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de pará-lo e carregar todos os módulos. Primeiro clique em _Debug >> Break All_ e depois clique em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg também conta com um launcher gráfico onde você pode selecionar as opções desejadas e executar o shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

A opção **Create Dump** irá fazer dump do shellcode final se alguma mudança for feita no shellcode dinamicamente na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal do scDbg (porém, considero qualquer uma das opções explicadas antes melhor para esse caso, pois você poderá usar o Ida ou x64dbg).

### Disassembling using CyberChef

Faça upload do arquivo do seu shellcode como entrada e use a seguinte recipe para decompilar: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

A obfuscation **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples como `x + y` por trás de fórmulas que misturam operadores aritméticos (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shifts). A parte importante é que essas identidades normalmente só são corretas sob **fixed-width modular arithmetic**, então carries e overflows importam:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, pode facilmente obter um resultado errado porque a semântica de largura de bits foi ignorada.

### Fluxo de trabalho prático

1. **Mantenha a largura original de bits** do código/IR/decompiler levantado (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
- **Linear**: somas ponderadas de átomos bitwise
- **Semilinear**: linear mais máscaras constantes como `x & 0xFF`
- **Polinomial**: aparecem produtos
- **Mista**: produtos e lógica bitwise estão intercalados, muitas vezes com subexpressões repetidas
3. **Verifique cada reescrita candidata** com testes aleatórios ou uma prova SMT. Se a equivalência não puder ser provada, mantenha a expressão original em vez de adivinhar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador MBA prático para análise de malware e reversing de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados, em vez de aplicar uma única passagem genérica de rewrite a tudo.

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

- **Linear MBA**: CoBRA avalia a expressão em entradas Booleanas, deriva uma assinatura e executa em paralelo vários métodos de recuperação, como pattern matching, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos mascarados por constantes são reconstruídos com reconstrução particionada por bits, para que as regiões mascaradas permaneçam corretas.
- **Polynomial/Mixed MBA**: produtos são decompostos em núcleos e subexpressões repetidas podem ser elevadas a temporários antes de simplificar a relação externa.

Exemplo de uma identidade mista que geralmente vale a pena tentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Isto pode se reduzir a:
```c
x * y
```
### Anotações de reversing

- Prefira executar CoBRA em **expressões IR lifted** ou na saída do decompiler depois de isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética mascarada ou de registradores estreitos.
- Se precisar de uma etapa de prova mais forte, confira as notas locais do Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA também vem como um **plugin de LLVM pass** (`libCobraPass.so`), o que é útil quando você quer normalizar LLVM IR com muito MBA antes de passes de análise posteriores.
- Resíduos mixed-domain sensíveis a carry sem suporte devem ser tratados como um sinal para manter a expressão original e raciocinar manualmente sobre o caminho do carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator **modifica todas as instruções para `mov`**(é, realmente muito legal). Ele também usa interruptions para mudar os fluxos de execução. Para mais informações sobre como funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se você tiver sorte, [demovfuscator](https://github.com/kirschju/demovfuscator) vai deofuscate o binário. Ele tem várias dependências
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, este workaround para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **ponto de entrada**, pesquise as funções por `::main` como em:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bem óbvio que esta é a função main interessante.\
Tendo o **nome** das **funções** chamadas, pesquise-as na **Internet** para aprender sobre suas **entradas** e **saídas**.

### Recovering Rust strings from ELF firmware

Em binários **Rust ELF**, muitas strings estáticas não são referenciadas como ponteiros NUL-terminated no estilo C. Um layout comum do `rustc` é uma **tupla ponteiro/tamanho** dentro de **`.data.rel.ro`** apontando para o blob real da string armazenado em **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Isso significa que `strings` ou a análise padrão do Ghidra podem mesclar strings adjacentes ou até perder referências cruzadas por completo.

Fluxo de trabalho rápido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtenha o endereço virtual e o tamanho de **`.rodata`**.
2. Enumere **`.data.rel.ro`** uma palavra por vez.
3. Trate qualquer valor dentro do intervalo de endereço de `.rodata` como um candidato a ponteiro de string.
4. Trate a próxima palavra como o comprimento candidato.
5. Aplique filtros de sanity (por exemplo, mantenha comprimentos entre **4** e **100** bytes).
6. Leia exatamente `length` bytes de `.rodata` em vez de varrer até `0x00`.

Lógica mínima do extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Isso é especialmente útil em firmware reversing porque strings Rust recuperadas frequentemente revelam **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers e lógica relacionada a auth**.

Se o Ghidra não encontrar essas strings, rode um script/plugin customizado que aplique a mesma heuristic e crie string data nos offsets `.rodata` referenciados. As ferramentas publicadas `rust-strings` e `RustStrings.py` da Pen Test Partners são boas referências para adaptar a ideia a outros **word sizes, endianness e section layouts**.

## **Delphi**

Para binaries compilados em Delphi você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se você tiver que fazer reverse de um binary Delphi, eu sugeriria usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta pressionar **ATL+f7** (import python plugin no IDA) e selecionar o python plugin.

Este plugin executará o binary e resolverá os nomes das funções dinamicamente no início da debugging. Depois de iniciar a debugging, pressione novamente o botão Start (o verde ou f9) e um breakpoint será atingido no início do código real.

Também é muito interessante porque, se você pressionar um botão na graphic application, o debugger vai parar na função executada por esse botão.

## Golang

Se você tiver que fazer reverse de um binary Golang, eu sugeriria usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta pressionar **ATL+f7** (import python plugin no IDA) e selecionar o python plugin.

Isso resolverá os nomes das funções.

## Compiled Python

Nesta página você pode encontrar como obter o código python de um binary compilado de ELF/EXE python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se você obtiver o **binary** de um jogo de GBA, pode usar diferentes ferramentas para **emular** e **debugar** ele:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de debug_) - Contém um debugger com interface
- [**mgba** ](https://mgba.io)- Contém um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

Em [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** ** você pode ver como pressionar os **buttons** do Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Quando pressionada, cada **key tem um valor** para identificá-la:
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
Então, nesse tipo de programa, a parte interessante será **como o programa trata a entrada do usuário**. No endereço **0x4000130** você encontrará a função comumente encontrada: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

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
O último `if` está verificando se **`uVar4`** está nas **últimas Keys** e não é a chave atual, também chamado de soltar um botão (a chave atual está armazenada em **`uVar1`**).
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
No código anterior você pode ver que estamos comparando **uVar1** (o lugar onde está o **valor do botão pressionado**) com alguns valores:

- Primeiro, ele é comparado com o **valor 4** (botão **SELECT**): No desafio, esse botão limpa a tela
- Depois, ele é comparado com o **valor 8** (botão **START**): No desafio, isso verifica se o código é válido para obter a flag.
- Neste caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for o mesmo, algum código é executado.
- Em qualquer outro caso, algum cont (**`DAT_030000d4`**) é verificado. É um cont porque ele está adicionando 1 logo após entrar no código.\
**S**e for menor que 8, algo que envolve **adicionar** valores a **`DAT_030000d8`** é feito (basicamente, ele adiciona os valores das teclas pressionadas nessa var enquanto o cont for menor que 8).

Então, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com comprimento menor que 8 cujo somatório resulte em 0xf3.**

**Referência para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desobfuscação binária)

## Referências

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
