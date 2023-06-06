<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Decompilador Wasm / Compilador Wat

Online:

* Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm \(binário\) para wat \(texto claro\)
* Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat para wasm
* você também pode tentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# Decompilador .Net

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)  
[Plugin ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Você pode tê-lo em qualquer sistema operacional \(você pode instalá-lo diretamente do VSCode, não é necessário baixar o git. Clique em **Extensões** e **pesquise ILSpy**\).  
Se você precisa **descompilar**, **modificar** e **recompilar** novamente, você pode usar: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) \(**Clique com o botão direito -&gt; Modificar Método** para mudar algo dentro de uma função\).  
Você também pode tentar [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

## DNSpy Logging

Para fazer com que o **DNSpy registre algumas informações em um arquivo**, você pode usar essas linhas .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## Depuração com DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, alterar os **atributos da Assembleia** relacionados à **depuração**:

![](../../.gitbook/assets/image%20%287%29.png)

De:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Para:
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
E clique em **compilar**:

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

Em seguida, salve o novo arquivo em _**Arquivo &gt;&gt; Salvar módulo...**_:

![](../../.gitbook/assets/image%20%28261%29.png)

Isso é necessário porque, se você não fizer isso, em **tempo de execução**, várias **otimizações** serão aplicadas ao código e pode ser possível que, ao depurar, um **ponto de interrupção nunca seja atingido** ou algumas **variáveis não existam**.

Então, se sua aplicação .Net está sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:
```text
iisreset /noforce
```
Então, para começar a depurar, você deve fechar todos os arquivos abertos e, dentro da **Guia de Depuração**, selecionar **Anexar ao Processo...**:

![](../../.gitbook/assets/image%20%28166%29.png)

Em seguida, selecione **w3wp.exe** para anexar ao **servidor IIS** e clique em **anexar**:

![](../../.gitbook/assets/image%20%28274%29.png)

Agora que estamos depurando o processo, é hora de pará-lo e carregar todos os módulos. Primeiro, clique em _Debug &gt;&gt; Break All_ e depois clique em _**Debug &gt;&gt; Windows &gt;&gt; Modules**_:

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

Clique em qualquer módulo em **Módulos** e selecione **Abrir Todos os Módulos**:

![](../../.gitbook/assets/image%20%28216%29.png)

Clique com o botão direito do mouse em qualquer módulo no **Explorador de Assembléias** e clique em **Classificar Assembléias**:

![](../../.gitbook/assets/image%20%28130%29.png)

# Decompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)  
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# Depurando DLLs

## Usando IDA

* **Carregue rundll32** \(64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe\)
* Selecione o depurador **Windbg**
* Selecione "**Suspender na carga/descarga da biblioteca**"

![](../../.gitbook/assets/image%20%2869%29.png)

* Configure os **parâmetros** da execução colocando o **caminho para a DLL** e a função que você deseja chamar:

![](../../.gitbook/assets/image%20%28325%29.png)

Então, quando você começa a depurar, **a execução será interrompida quando cada DLL for carregada**, então, quando o rundll32 carregar sua DLL, a execução será interrompida.

Mas como você pode chegar ao código da DLL que foi carregada? Usando este método, eu não sei como.

## Usando x64dbg/x32dbg

* **Carregue rundll32** \(64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe\)
* **Altere a Linha de Comando** \( _Arquivo --&gt; Alterar Linha de Comando_ \) e defina o caminho da dll e a função que você deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* Altere _Opções --&gt; Configurações_ e selecione "**Entrada de DLL**".
* Em seguida, **inicie a execução**, o depurador irá parar em cada dll principal, em algum momento você irá **parar na Entrada da DLL da sua dll**. A partir daí, basta procurar os pontos onde você deseja colocar um ponto de interrupção.

Observe que quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código você está** olhando na **parte superior da janela do win64dbg**:

![](../../.gitbook/assets/image%20%28181%29.png)

Então, olhando para isso, você pode ver quando a execução foi interrompida na dll que você deseja depurar.

# ARM & MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# Shellcodes

## Depurando um shellcode com blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) irá **alocar** o **shellcode** dentro de um espaço de memória, irá **indicar** o **endereço de memória** onde o shellcode foi alocado e irá **parar** a execução.  
Em seguida, você precisa **anexar um depurador** \(Ida ou x64dbg\) ao processo e colocar um **ponto de interrupção no endereço de memória indicado** e **continuar** a execução. Dessa forma, você estará depurando o shellcode.

A página de lançamentos do github contém zips contendo os lançamentos compilados: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)  
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no seguinte link. Para compilá-lo, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.

{% page-ref page="blobrunner.md" %}

## Depurando um shellcode com jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)é muito semelhante ao blobrunner. Ele irá **alocar** o **shellcode** dentro de um espaço de memória e iniciar um **loop eterno**. Em seguida, você precisa **anexar o depurador** ao processo, **iniciar a execução, esperar 2-5 segundos e pressionar parar** e você se encontrará dentro do **loop eterno**. Pule para a próxima instrução do loop eterno, pois será uma chamada ao shellcode, e finalmente você se encontrará executando o shellcode.

![](../../.gitbook/assets/image%20%28403%29.png)

Você pode baixar uma versão compilada do [jmp2it dentro da página de lançamentos](https://github.com/adamkramer/jmp2it/releases/).

## Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a GUI do radare. Usando o cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite "Abrir Arquivo" e "Abrir Shellcode". No meu caso, quando abri o shellcode como arquivo, ele o descompilou corretamente, mas quando o abri como shellcode, não o fez:

![](../../.gitbook/assets/image%20%28254%29.png)

Para iniciar a emulação no local desejado, defina um bp lá e aparentemente o cutter iniciará automaticamente a emulação a partir daí:

![](../../.gitbook/assets/image%20%28402%29.png)

![](../../.gitbook/assets/image%20%28343%29.png)

Você pode ver a pilha, por exemplo, dentro de um despejo hexadecimal:

![](../../.gitbook/assets/image%20%28404%29.png)

## Desofuscando shellcode e obtendo funções executadas

Você deve tentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).  
Ele irá informar coisas como **quais funções** o shellcode está usando e se o shellcode está **decodificando** a si mesmo na memória.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
O scDbg também conta com um lançador gráfico onde você pode selecionar as opções desejadas e executar o shellcode.

![](../../.gitbook/assets/image%20%28401%29.png)

A opção **Create Dump** fará o dump do shellcode final se alguma alteração for feita no shellcode dinamicamente na memória \(útil para baixar o shellcode decodificado\). O **start offset** pode ser útil para iniciar o shellcode em um offset específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal scDbg \(no entanto, acho que qualquer uma das opções explicadas anteriormente é melhor para esse assunto, pois você poderá usar o Ida ou o x64dbg\).

## Desmontando usando o CyberChef

Carregue o arquivo do seu shellcode como entrada e use a seguinte receita para descompilá-lo: [https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador muda todas as instruções para `mov` \(sim, muito legal\). Ele também usa interrupções para mudar os fluxos de execução. Para obter mais informações sobre como funciona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se você tiver sorte, o [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará o binário. Ele tem várias dependências.
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instale o keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

Se você está jogando um **CTF, esta solução alternativa para encontrar a flag** pode ser muito útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html) 

# Delphi

Para binários compilados em Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Desofuscação binária\)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
