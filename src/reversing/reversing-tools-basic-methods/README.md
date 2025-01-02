# Ferramentas de Reversão & Métodos Básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de Reversão Baseadas em ImGui

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

dotPeek é um descompilador que **descompila e examina múltiplos formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Uma vez descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

O mérito aqui é que se um código fonte perdido requer restauração de um assembly legado, essa ação pode economizar tempo. Além disso, dotPeek fornece navegação prática por todo o código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo de add-in abrangente e uma API que estende a ferramenta para atender às suas necessidades exatas, .NET Reflector economiza tempo e simplifica o desenvolvimento. Vamos dar uma olhada na infinidade de serviços de engenharia reversa que esta ferramenta fornece:

- Fornece uma visão de como os dados fluem através de uma biblioteca ou componente
- Fornece insights sobre a implementação e uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para obter mais das APIs e tecnologias utilizadas.
- Encontra dependências e diferentes assemblies
- Localiza exatamente a origem de erros no seu código, componentes de terceiros e bibliotecas.
- Depura a origem de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode tê-lo em qualquer sistema operacional (pode instalá-lo diretamente do VSCode, sem necessidade de baixar o git. Clique em **Extensões** e **pesquise ILSpy**).\
Se você precisar **descompilar**, **modificar** e **recompilar** novamente, pode usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork ativamente mantido dele, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modificar Método** para alterar algo dentro de uma função).

### Registro DNSpy

Para fazer com que **DNSpy registre algumas informações em um arquivo**, você pode usar este trecho:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuração com DNSpy

Para depurar código usando DNSpy, você precisa:

Primeiro, alterar os **atributos de Assembly** relacionados à **depuração**:

![](<../../images/image (973).png>)
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

Em seguida, salve o novo arquivo via _**File >> Save module...**_:

![](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, durante a **execução** várias **otimizações** serão aplicadas ao código e pode ser possível que, ao depurar, um **ponto de interrupção nunca seja atingido** ou algumas **variáveis não existam**.

Então, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:
```
iisreset /noforce
```
Então, para começar a depuração, você deve fechar todos os arquivos abertos e, dentro da **Debug Tab**, selecionar **Attach to Process...**:

![](<../../images/image (318).png>)

Em seguida, selecione **w3wp.exe** para anexar ao **IIS server** e clique em **attach**:

![](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de pará-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e depois clique em _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo em **Assembly Explorer** e clique em **Sort Assemblies**:

![](<../../images/image (339).png>)

## Decompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depurando DLLs

### Usando IDA

- **Carregar rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecionar o depurador **Windbg**
- Selecionar "**Suspender na carga/descarregamento da biblioteca**"

![](<../../images/image (868).png>)

- Configurar os **parâmetros** da execução colocando o **caminho para a DLL** e a função que você deseja chamar:

![](<../../images/image (704).png>)

Então, quando você começar a depurar, **a execução será interrompida quando cada DLL for carregada**, então, quando o rundll32 carregar sua DLL, a execução será interrompida.

Mas, como você pode chegar ao código da DLL que foi carregada? Usando este método, eu não sei como.

### Usando x64dbg/x32dbg

- **Carregar rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Mudar a Linha de Comando** (_File --> Change Command Line_) e definir o caminho da dll e a função que você deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Mudar _Options --> Settings_ e selecionar "**DLL Entry**".
- Então **iniciar a execução**, o depurador irá parar em cada main da dll, em algum momento você irá **parar na entrada da dll da sua dll**. A partir daí, basta procurar os pontos onde você deseja colocar um breakpoint.

Observe que quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código você está** olhando no **topo da janela do win64dbg**:

![](<../../images/image (842).png>)

Então, olhando para isso, você pode ver quando a execução foi interrompida na dll que você deseja depurar.

## Aplicativos GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos dentro da memória de um jogo em execução e alterá-los. Mais informações em:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta de front-end/reverse engineering para o GNU Project Debugger (GDB), focada em jogos. No entanto, pode ser usada para qualquer coisa relacionada a engenharia reversa.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompiladores. Este serviço web permite que você compare a saída de diferentes decompiladores em pequenos executáveis.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Depurando um shellcode com blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) irá **alocar** o **shellcode** dentro de um espaço de memória, irá **indicar** o **endereço de memória** onde o shellcode foi alocado e irá **parar** a execução.\
Então, você precisa **anexar um depurador** (Ida ou x64dbg) ao processo e colocar um **breakpoint no endereço de memória indicado** e **retomar** a execução. Dessa forma, você estará depurando o shellcode.

A página de lançamentos do github contém zips com os lançamentos compilados: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no seguinte link. Para compilá-lo, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilar**.

{{#ref}}
blobrunner.md
{{#endref}}

### Depurando um shellcode com jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é muito semelhante ao blobrunner. Ele irá **alocar** o **shellcode** dentro de um espaço de memória e iniciar um **loop eterno**. Você então precisa **anexar o depurador** ao processo, **iniciar, esperar 2-5 segundos e pressionar parar** e você se encontrará dentro do **loop eterno**. Salte para a próxima instrução do loop eterno, pois será uma chamada ao shellcode, e finalmente você se encontrará executando o shellcode.

![](<../../images/image (509).png>)

Você pode baixar uma versão compilada de [jmp2it na página de lançamentos](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite que você "Abra Arquivo" e "Abra Shellcode". No meu caso, quando abri o shellcode como um arquivo, ele o decompilou corretamente, mas quando o abri como um shellcode, não:

![](<../../images/image (562).png>)

Para iniciar a emulação no lugar que você deseja, defina um bp lá e aparentemente o cutter começará automaticamente a emulação a partir daí:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Você pode ver a pilha, por exemplo, dentro de um dump hex:

![](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo funções executadas

Você deve tentar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele irá te informar coisas como **quais funções** o shellcode está usando e se o shellcode está **decodificando** a si mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg também conta com um lançador gráfico onde você pode selecionar as opções que deseja e executar o shellcode.

![](<../../images/image (258).png>)

A opção **Create Dump** irá despejar o shellcode final se alguma alteração for feita no shellcode dinamicamente na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um deslocamento específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal scDbg (no entanto, eu acho que qualquer uma das opções explicadas antes é melhor para isso, pois você poderá usar o Ida ou x64dbg).

### Desmontando usando CyberChef

Carregue seu arquivo de shellcode como entrada e use a seguinte receita para decompilá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador **modifica todas as instruções para `mov`** (sim, realmente legal). Ele também usa interrupções para mudar os fluxos de execução. Para mais informações sobre como funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se você tiver sorte, [demovfuscator](https://github.com/kirschju/demovfuscator) irá deofuscar o binário. Ele tem várias dependências.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, essa solução alternativa para encontrar a bandeira** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **ponto de entrada**, pesquise as funções por `::main` como em:

![](<../../images/image (1080).png>)

Neste caso, o binário foi chamado de authenticator, então é bem óbvio que esta é a função principal interessante.\
Tendo o **nome** das **funções** sendo chamadas, pesquise por elas na **Internet** para aprender sobre suas **entradas** e **saídas**.

## **Delphi**

Para binários compilados em Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se você precisar reverter um binário Delphi, eu sugeriria usar o plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta pressionar **ATL+f7** (importar plugin python no IDA) e selecionar o plugin python.

Este plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Iniciar (o verde ou f9) e um ponto de interrupção será atingido no início do código real.

É também muito interessante porque se você pressionar um botão na aplicação gráfica, o depurador parará na função executada por esse botão.

## Golang

Se você precisar reverter um binário Golang, eu sugeriria usar o plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta pressionar **ATL+f7** (importar plugin python no IDA) e selecionar o plugin python.

Isso resolverá os nomes das funções.

## Python Compilado

Nesta página você pode encontrar como obter o código python de um binário python compilado ELF/EXE:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se você obtiver o **binário** de um jogo GBA, pode usar diferentes ferramentas para **emular** e **depurar**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de depuração_) - Contém um depurador com interface
- [**mgba** ](https://mgba.io)- Contém um depurador CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

Em [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_\*\* \*\* você pode ver como pressionar os **botões** do Game Boy Advance

![](<../../images/image (581).png>)

Quando pressionado, cada **tecla tem um valor** para identificá-la:
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
Então, neste tipo de programa, a parte interessante será **como o programa trata a entrada do usuário**. No endereço **0x4000130** você encontrará a função comumente encontrada: **KEYINPUT**.

![](<../../images/image (447).png>)

Na imagem anterior, você pode ver que a função é chamada de **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

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
Encontrou este código:
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
A última verificação está checando se **`uVar4`** está nas **últimas Chaves** e não é a chave atual, também chamada de soltar um botão (a chave atual está armazenada em **`uVar1`**).
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
No código anterior, você pode ver que estamos comparando **uVar1** (o lugar onde está o **valor do botão pressionado**) com alguns valores:

- Primeiro, é comparado com o **valor 4** (botão **SELECT**): No desafio, este botão limpa a tela.
- Em seguida, é comparado com o **valor 8** (botão **START**): No desafio, isso verifica se o código é válido para obter a bandeira.
- Neste caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for o mesmo, algum código é executado.
- Em qualquer outro caso, algum cont (`DAT_030000d4`) é verificado. É um cont porque está adicionando 1 logo após entrar no código.\
**Se** for menor que 8, algo que envolve **adicionar** valores a \*\*`DAT_030000d8` \*\* é feito (basicamente, está adicionando os valores das teclas pressionadas nesta variável, desde que o cont seja menor que 8).

Portanto, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com um comprimento menor que 8 que a adição resultante seja 0xf3.**

**Referência para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscação binária)

{{#include ../../banners/hacktricks-training.md}}
