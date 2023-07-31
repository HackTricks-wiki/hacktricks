# Ferramentas de Reversão e Métodos Básicos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Ferramentas de Reversão Baseadas em ImGui

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilador Wasm / Compilador Wat

Online:

* Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binário) para wat (texto claro)
* Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
* você também pode tentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilador .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek é um decompilador que **descompila e examina vários formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Uma vez descompilado, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

O mérito aqui é que se um código-fonte perdido requer restauração de um assembly legado, essa ação pode economizar tempo. Além disso, o dotPeek fornece navegação prática por todo o código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos Xamarin.**&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de complementos e uma API que estende a ferramenta para atender às suas necessidades exatas, o .NET reflector economiza tempo e simplifica o desenvolvimento. Vamos dar uma olhada na infinidade de serviços de engenharia reversa que essa ferramenta oferece:

* Fornece uma visão de como os dados fluem por uma biblioteca ou componente
* Fornece insights sobre a implementação e o uso de linguagens e estruturas .NET
* Encontra funcionalidades não documentadas e não expostas para obter mais das APIs e tecnologias utilizadas.
* Encontra dependências e diferentes assemblies
* Localiza exatamente a localização de erros em seu código, componentes de terceiros e bibliotecas.&#x20;
* Depura o código-fonte de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode tê-lo em qualquer sistema operacional (você pode instalá-lo diretamente do VSCode, não é necessário baixar o git. Clique em **Extensões** e **pesquise ILSpy**).\
Se você precisa **descompilar**, **modificar** e **recompilar** novamente, você pode usar: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Clique com o botão direito -> Modificar Método** para alterar algo dentro de uma função).\
Você também pode tentar [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy Logging

Para fazer com que o **DNSpy registre algumas informações em um arquivo**, você pode usar estas linhas .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuração com DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, altere os **atributos de montagem** relacionados à **depuração**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Para:

# Ferramentas de Reversão - Métodos Básicos

Este repositório contém uma coleção de ferramentas de reversão e métodos básicos para ajudar os hackers a analisar e entender o funcionamento interno de um software. Essas ferramentas são essenciais para a engenharia reversa e podem ser usadas para identificar vulnerabilidades, encontrar falhas de segurança e explorar sistemas.

## Ferramentas de Reversão

As ferramentas de reversão são programas que ajudam os hackers a analisar e modificar o código de um software. Essas ferramentas permitem que os hackers examinem o código-fonte, identifiquem funções e variáveis importantes e modifiquem o comportamento do software.

Algumas das ferramentas de reversão mais populares incluem:

- **IDA Pro**: Uma ferramenta de engenharia reversa líder de mercado que permite aos hackers analisar e modificar o código de um software.
- **OllyDbg**: Um depurador de código de baixo nível que permite aos hackers examinar e modificar o código de um software em tempo de execução.
- **Ghidra**: Uma ferramenta de engenharia reversa de código aberto desenvolvida pela Agência de Segurança Nacional dos Estados Unidos (NSA).

## Métodos Básicos de Reversão

Existem vários métodos básicos que os hackers podem usar para analisar e entender o código de um software. Esses métodos incluem:

- **Análise Estática**: A análise estática envolve a revisão do código-fonte ou do código de máquina de um software sem executá-lo. Isso permite que os hackers identifiquem funções, variáveis e fluxos de controle importantes.
- **Análise Dinâmica**: A análise dinâmica envolve a execução de um software em um ambiente controlado para observar seu comportamento. Isso permite que os hackers identifiquem vulnerabilidades, falhas de segurança e comportamentos indesejados.
- **Engenharia Reversa de Protocolo**: A engenharia reversa de protocolo envolve a análise de um protocolo de comunicação para entender como ele funciona. Isso permite que os hackers identifiquem vulnerabilidades e explorem sistemas que usam esse protocolo.
- **Desmontagem**: A desmontagem envolve a conversão do código de máquina em uma representação legível por humanos. Isso permite que os hackers analisem o código de um software em um nível mais baixo e identifiquem vulnerabilidades e falhas de segurança.

Esses métodos básicos de reversão são fundamentais para a análise de software e a identificação de vulnerabilidades. Os hackers devem estar familiarizados com essas ferramentas e métodos para ter sucesso na engenharia reversa e na exploração de sistemas.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
E clique em **compilar**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Em seguida, salve o novo arquivo em _**Arquivo >> Salvar módulo...**_:

![](<../../.gitbook/assets/image (279).png>)

Isso é necessário porque se você não fizer isso, durante a **execução** várias **otimizações** serão aplicadas ao código e pode ser possível que, ao depurar, um **ponto de interrupção nunca seja atingido** ou algumas **variáveis não existam**.

Em seguida, se sua aplicação .Net está sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:
```
iisreset /noforce
```
Em seguida, para iniciar a depuração, você deve fechar todos os arquivos abertos e, dentro da **Guia de Depuração**, selecionar **Anexar ao Processo...**:

![](<../../.gitbook/assets/image (280).png>)

Em seguida, selecione **w3wp.exe** para anexar ao servidor **IIS** e clique em **anexar**:

![](<../../.gitbook/assets/image (281).png>)

Agora que estamos depurando o processo, é hora de pará-lo e carregar todos os módulos. Primeiro, clique em _Depurar >> Parar Todos_ e depois clique em _**Depurar >> Janelas >> Módulos**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Clique em qualquer módulo em **Módulos** e selecione **Abrir Todos os Módulos**:

![](<../../.gitbook/assets/image (284).png>)

Clique com o botão direito em qualquer módulo em **Explorador de Assemblies** e clique em **Ordenar Assemblies**:

![](<../../.gitbook/assets/image (285).png>)

## Decompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuração de DLLs

### Usando o IDA

* **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
* Selecione o depurador **Windbg**
* Selecione "**Suspender ao carregar/descarregar biblioteca**"

![](<../../.gitbook/assets/image (135).png>)

* Configure os **parâmetros** da execução colocando o **caminho para a DLL** e a função que você deseja chamar:

![](<../../.gitbook/assets/image (136).png>)

Então, quando você iniciar a depuração, a **execução será interrompida quando cada DLL for carregada**, então, quando o rundll32 carregar sua DLL, a execução será interrompida.

Mas, como você pode chegar ao código da DLL que foi carregada? Usando esse método, eu não sei como.

### Usando x64dbg/x32dbg

* **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
* **Altere a Linha de Comando** ( _Arquivo --> Alterar Linha de Comando_ ) e defina o caminho da DLL e a função que você deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Altere _Opções --> Configurações_ e selecione "**DLL Entry**".
* Em seguida, **inicie a execução**, o depurador irá parar em cada dll main, em algum momento você irá **parar na DLL Entry da sua DLL**. A partir daí, basta procurar os pontos onde você deseja colocar um ponto de interrupção.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código você está** olhando na **parte superior da janela do win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Então, olhando para isso, você pode ver quando a execução foi interrompida na DLL que você deseja depurar.

## Aplicativos GUI / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos na memória de um jogo em execução e alterá-los. Mais informações em:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Depurando um shellcode com blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) irá **alocar** o **shellcode** dentro de um espaço de memória, irá **indicar** o **endereço de memória** onde o shellcode foi alocado e irá **parar** a execução.\
Em seguida, você precisa **anexar um depurador** (Ida ou x64dbg) ao processo e colocar um **ponto de interrupção no endereço de memória indicado** e **continuar** a execução. Dessa forma, você estará depurando o shellcode.

A página de lançamentos do GitHub contém zips contendo os lançamentos compilados: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no seguinte link. Para compilá-lo, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Depurando um shellcode com jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)é muito semelhante ao blobrunner. Ele irá **alocar** o **shellcode** dentro de um espaço de memória e iniciar um **loop eterno**. Em seguida, você precisa **anexar o depurador** ao processo, **iniciar, esperar 2-5 segundos e pressionar parar** e você se encontrará dentro do **loop eterno**. Pule para a próxima instrução do loop eterno, pois será uma chamada ao shellcode, e finalmente você se encontrará executando o shellcode.

![](<../../.gitbook/assets/image (397).png>)

Você pode baixar uma versão compilada do [jmp2it na página de lançamentos](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite "Abrir Arquivo" e "Abrir Shellcode". No meu caso, quando abri o shellcode como arquivo, ele descompilou corretamente, mas quando abri como shellcode, não:

![](<../../.gitbook/assets/image (400).png>)

Para iniciar a emulação no local desejado, defina um bp lá e aparentemente o cutter iniciará automaticamente a emulação a partir daí:

![](<../../.gitbook/assets/image (399).png>)

Você pode ver a pilha, por exemplo, dentro de um dump hexadecimal:

![](<../../.gitbook/assets/image (402).png>)
### Desofuscando shellcode e obtendo funções executadas

Você deve tentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Ele irá informar coisas como **quais funções** o shellcode está usando e se o shellcode está **decodificando** a si mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg também conta com um lançador gráfico onde você pode selecionar as opções desejadas e executar o shellcode

![](<../../.gitbook/assets/image (398).png>)

A opção **Create Dump** fará o dump do shellcode final se alguma alteração for feita dinamicamente na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um deslocamento específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal scDbg (no entanto, acho que qualquer uma das opções explicadas anteriormente é melhor para esse assunto, pois você poderá usar o Ida ou x64dbg).

### Desmontando usando o CyberChef

Faça o upload do seu arquivo de shellcode como entrada e use a seguinte receita para descompilá-lo: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador **modifica todas as instruções para `mov`** (sim, muito legal). Ele também usa interrupções para alterar os fluxos de execução. Para obter mais informações sobre como funciona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Se você tiver sorte, o [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará o binário. Ele tem várias dependências.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se você estiver jogando um **CTF, essa solução alternativa para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar o **ponto de entrada**, procure as funções por `::main` como em:

![](<../../.gitbook/assets/image (612).png>)

Neste caso, o binário foi chamado de authenticator, então é bem óbvio que esta é a função principal interessante.\
Tendo o **nome** das **funções** sendo chamadas, pesquise sobre elas na **Internet** para aprender sobre suas **entradas** e **saídas**.

## **Delphi**

Para binários compilados em Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se você precisar reverter um binário Delphi, sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta pressionar **ATL+f7** (importar plugin python no IDA) e selecionar o plugin python.

Este plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Iniciar (o verde ou f9) e um ponto de interrupção será acionado no início do código real.

Também é muito interessante porque se você pressionar um botão na aplicação gráfica, o depurador irá parar na função executada por esse botão.

## Golang

Se você precisar reverter um binário Golang, sugiro usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta pressionar **ATL+f7** (importar plugin python no IDA) e selecionar o plugin python.

Isso resolverá os nomes das funções.

## Python compilado

Nesta página, você pode aprender como obter o código Python de um binário compilado ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Se você tiver o **binário** de um jogo GBA, você pode usar diferentes ferramentas para **emular** e **depurar**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de depuração_) - Contém um depurador com interface
* [**mgba** ](https://mgba.io)- Contém um depurador CLI
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_\*\* \*\* você pode ver como pressionar os **botões** do Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

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
Então, nesse tipo de programa, uma parte interessante será **como o programa trata a entrada do usuário**. No endereço **0x4000130**, você encontrará a função comumente encontrada: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

Na imagem anterior, você pode ver que a função é chamada de **FUN_080015a8** (endereços: _0x080015fa_ e _0x080017ac_).

Nessa função, após algumas operações de inicialização (sem importância alguma):
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
O último "if" verifica se **`uVar4`** está nas **últimas teclas** e não é a tecla atual, também conhecida como soltar um botão (a tecla atual é armazenada em **`uVar1`**).
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

* Primeiro, é comparado com o **valor 4** (botão **SELECT**): Neste desafio, esse botão limpa a tela.
* Em seguida, é comparado com o **valor 8** (botão **START**): Neste desafio, isso verifica se o código é válido para obter a bandeira.
* Neste caso, a variável **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for o mesmo, algum código é executado.
* Em todos os outros casos, é verificado um contador (`DAT_030000d4`). É um contador porque ele adiciona 1 logo após entrar no código.\
Se for menor que 8, algo que envolve **adicionar** valores a \*\*`DAT_030000d8` \*\* é feito (basicamente, está adicionando os valores dos botões pressionados nesta variável, desde que o contador seja menor que 8).

Portanto, neste desafio, sabendo os valores dos botões, você precisava **pressionar uma combinação com um comprimento menor que 8 para que a adição resultante seja 0xf3**.

**Referência para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desobfuscação binária)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
