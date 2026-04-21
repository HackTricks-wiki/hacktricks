# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de Reversing Baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompiler Wasm / Compilador Wat

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binary) para wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
- você também pode tentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para decompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek é um decompiler que **decompila e examina múltiplos formatos**, incluindo **libraries** (.dll), **Windows metadata file**s (.winmd) e **executables** (.exe). Uma vez decompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem aqui é que, se um código-fonte perdido precisar ser restaurado a partir de um assembly legada, essa ação pode economizar tempo. Além disso, o dotPeek oferece navegação prática por todo o código decompilado, tornando-o uma das ferramentas perfeitas para **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-in e uma API que estende a ferramenta para atender às suas necessidades exatas, o .NET reflector economiza tempo e simplifica o desenvolvimento. Vamos analisar a variedade de serviços de reverse engineering que esta ferramenta fornece:

- Fornece uma visão sobre como os dados fluem por uma library ou componente
- Fornece insight sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades sem documentação e não expostas para obter mais das APIs e tecnologias usadas.
- Encontra dependências e diferentes assemblies
- Localiza a posição exata de erros no seu código, componentes de terceiros e libraries.
- Faz debug na origem de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode usá-lo em qualquer OS (você pode instalá-lo diretamente pelo VSCode, sem necessidade de baixar o git. Clique em **Extensions** e **search ILSpy**).\
Se você precisar **decompilar**, **modificar** e **recompilar** novamente, pode usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork dele mantido ativamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** para alterar algo dentro de uma função).

### DNSpy Logging

Para fazer o **DNSpy registrar alguma informação em um arquivo**, você pode usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Para debugar código usando DNSpy você precisa:

Primeiro, alterar os **Assembly attributes** relacionados a **debugging**:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

Depois, salve o novo arquivo via _**File >> Save module...**_:

![](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, em **runtime** várias **optimisations** serão aplicadas ao código e pode ser possível que, durante o debugging, um **break-point** nunca seja atingido ou que algumas **variables** não existam.

Então, se sua aplicação .NET estiver sendo **run** pelo **IIS**, você pode **restart** ela com:
```
iisreset /noforce
```
Então, para começar a depuração você deve fechar todos os arquivos abertos e, dentro da **Debug Tab**, selecionar **Attach to Process...**:

![](<../../images/image (318).png>)

Depois selecione **w3wp.exe** para anexar ao **IIS server** e clique em **attach**:

![](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de pará-lo e carregar todos os módulos. Primeiro clique em _Debug >> Break All_ e depois clique em _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo no **Assembly Explorer** e clique em **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Selecione o debugger **Windbg**
- Selecione "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure os **parameters** de execução colocando o **path to the DLL** e a função que você quer chamar:

![](<../../images/image (704).png>)

Então, quando você iniciar a depuração, **a execução será interrompida quando cada DLL for carregada**, e quando o rundll32 carregar sua DLL a execução será interrompida.

Mas como você pode chegar ao código da DLL que foi carregada? Usando esse método, eu não sei como.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) e defina o path da dll e a função que você quer chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Então **inicie a execução**, o debugger vai parar em cada dll main, em algum momento você vai **parar na dll Entry da sua dll**. A partir daí, basta procurar os pontos onde você quer colocar um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código você está** olhando na **parte superior da janela do win64dbg**:

![](<../../images/image (842).png>)

Então, observando isso, veja quando a execução foi interrompida na dll que você quer depurar.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes estão salvos na memória de um jogo em execução e alterá-los. Mais info em:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta front-end/reverse engineering para o GNU Project Debugger (GDB), focada em jogos. No entanto, pode ser usada para qualquer coisa relacionada a reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompilers. Esse serviço web permite comparar a saída de diferentes decompilers em pequenos executáveis.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) vai **alocar** o **shellcode** dentro de um espaço de memória, vai **indicar** o **endereço de memória** onde o shellcode foi alocado e vai **parar** a execução.\
Depois, você precisa **anexar um debugger** (Ida ou x64dbg) ao processo e colocar **um breakpoint no endereço de memória indicado** e **retomar** a execução. Dessa forma, você estará depurando o shellcode.

A página de releases no github contém zips com as versões compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão levemente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é muito similar ao blobrunner. Ele vai **alocar** o **shellcode** dentro de um espaço de memória e iniciar um **eternal loop**. Então você precisa **anexar o debugger** ao processo, **play start wait 2-5 secs and press stop** e você vai se encontrar dentro do **eternal loop**. Vá para a próxima instrução do eternal loop, pois ela será uma chamada ao shellcode, e por fim você se encontrará executando o shellcode.

![](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o cutter você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite **"Open File"** e **"Open Shellcode"**. No meu caso, quando abri o shellcode como arquivo ele o decompilou corretamente, mas quando o abri como shellcode não:

![](<../../images/image (562).png>)

Para iniciar a emulação no ponto desejado, defina um bp ali e aparentemente o cutter vai iniciar automaticamente a emulação a partir dali:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Você pode ver a stack, por exemplo, dentro de um hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Você deve tentar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele vai te dizer coisas como **quais funções** o shellcode está usando e se o shellcode está **decoding** ele mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg também conta com um launcher gráfico onde você pode selecionar as opções desejadas e executar o shellcode

![](<../../images/image (258).png>)

A opção **Create Dump** irá fazer dump do shellcode final se alguma alteração for feita no shellcode dinamicamente na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para debugar o shellcode usando o terminal do scDbg (porém eu acho qualquer uma das opções explicadas antes melhor para esse caso, já que você poderá usar Ida ou x64dbg).

### Disassembling using CyberChef

Faça upload do seu arquivo de shellcode como entrada e use a seguinte receita para decompilar ele: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

A obfuscação **Mixed Boolean-Arithmetic (MBA)** esconde expressões simples como `x + y` atrás de fórmulas que misturam operadores aritméticos (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shifts). A parte importante é que essas identidades geralmente só estão corretas sob **aritmética modular de largura fixa**, então carries e overflows importam:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se você simplificar esse tipo de expressão com ferramentas algébricas genéricas, pode facilmente obter um resultado errado porque a semântica da largura de bits foi ignorada.

### Fluxo de trabalho prático

1. **Mantenha a largura de bits original** do código/IR/decompiler output levantado (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
- **Linear**: somas ponderadas de átomos bitwise
- **Semilinear**: linear mais máscaras constantes como `x & 0xFF`
- **Polynomial**: products appear
- **Mixed**: products and bitwise logic are interleaved, often with repeated subexpressions
3. **Verifique cada rewrite candidato** com testes aleatórios ou uma prova SMT. Se a equivalência não puder ser provada, mantenha a expressão original em vez de adivinhar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador MBA prático para análise de malware e reversing de binários protegidos. Ele classifica a expressão e a encaminha por pipelines especializados em vez de aplicar um único rewrite pass genérico a tudo.

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

- **Linear MBA**: CoBRA avalia a expressão em entradas Boolean, deriva uma assinatura e compara vários métodos de recuperação, como pattern matching, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos com máscara constante são reconstruídos com reconstrução particionada por bits, para que as regiões mascaradas permaneçam corretas.
- **Polynomial/Mixed MBA**: produtos são decompostos em núcleos e subexpressões repetidas podem ser promovidas para temporários antes de simplificar a relação externa.

Exemplo de uma identidade mixed comumente que vale a pena tentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Isso pode se reduzir a:
```c
x * y
```
### Reversing notes

- Prefira executar CoBRA em **lifted IR expressions** ou saída de decompiler depois de isolar a computação exata.
- Use `--bitwidth` explicitamente quando a expressão vier de masked arithmetic ou registradores estreitos.
- Se você precisar de um passo de prova mais forte, confira as notas locais do Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA também vem como um **LLVM pass plugin** (`libCobraPass.so`), o que é útil quando você quer normalizar LLVM IR com muito MBA antes de etapas posteriores de análise.
- Resíduos mistos de domínio com carry-sensitive não suportados devem ser tratados como um sinal para manter a expressão original e raciocinar manualmente sobre o caminho do carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se você tiver sorte [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E instale o **keystone** ([https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, esse workaround para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **entry point** pesquise as funções por `::main` como em:

![](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bem óbvio que essa é a função main interessante.\
Tendo o **nome** das **funções** sendo chamadas, pesquise por elas na **Internet** para aprender sobre suas **entradas** e **saídas**.

## **Delphi**

Para binários compilados em Delphi você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se você precisar fazer reverse de um binário Delphi, eu sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta pressionar **ATL+f7** (import python plugin in IDA) e selecionar o plugin python.

Este plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Start (o verde ou f9) e um breakpoint será acionado no início do código real.

Isso também é muito interessante porque, se você pressionar um botão na aplicação gráfica, o debugger vai parar na função executada por esse botão.

## Golang

Se você tiver que fazer reverse de um binário Golang, eu sugiro usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta pressionar **ATL+f7** (import python plugin in IDA) e selecionar o plugin python.

Isso resolverá os nomes das funções.

## Compiled Python

Nesta página você pode encontrar como obter o código python de um binário ELF/EXE compilado em python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se você obtiver o **binário** de um jogo de GBA, você pode usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de debug_) - Contém um debugger com interface
- [**mgba** ](https://mgba.io)- Contém um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

Em [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** ** você pode ver como pressionar os **botões** do Game Boy Advance

![](<../../images/image (581).png>)

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
Então, nesse tipo de programa, a parte interessante será **como o programa trata a entrada do usuário**. No endereço **0x4000130** você encontrará a função comumente encontrada: **KEYINPUT**.

![](<../../images/image (447).png>)

Na imagem anterior você pode ver que a função é chamada a partir de **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

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
O último if está verificando se **`uVar4`** está nas **últimas Keys** e não é a key atual, também chamado de soltar um botão (a key atual está armazenada em **`uVar1`**).
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
- Depois, ele é comparado com o **valor 8** (botão **START**): no desafio, isso verifica se o código é válido para obter a flag.
- Nesse caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for o mesmo, algum código é executado.
- Em qualquer outro caso, algum cont (**`DAT_030000d4`**) é verificado. É um cont porque ele soma 1 logo após entrar no código.\
**S**e for menor que 8, algo que envolve **adicionar** valores a **`DAT_030000d8`** é feito (basicamente, ele soma os valores das teclas pressionadas nessa variável enquanto o cont for menor que 8).

Então, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com comprimento menor que 8 cujo somatório resulte em 0xf3.**

**Referência para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Referências

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)

{{#include ../../banners/hacktricks-training.md}}
