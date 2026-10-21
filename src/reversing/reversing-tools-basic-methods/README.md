# Ferramentas de reversing e métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Ferramentas de reversing baseadas em ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automação de user-mode no WinDbg

{{#ref}}
windbg-automation.md
{{#endref}}

## Fluxo de controle baseado em exceções no Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

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

## Payloads virtualizados e VMs customizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

O dotPeek é um descompilador que **descompila e examina vários formatos**, incluindo **bibliotecas** (.dll), **arquivos de metadados do Windows** (.winmd) e **executáveis** (.exe). Após a descompilação, um assembly pode ser salvo como um projeto do Visual Studio (.csproj).

A vantagem é que, se for necessário restaurar um código-fonte perdido a partir de um assembly legado, isso pode economizar tempo. Além disso, o dotPeek oferece uma navegação prática pelo código descompilado, tornando-o uma das ferramentas perfeitas para **análise de algoritmos do Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Com um modelo abrangente de add-ins e uma API que amplia a ferramenta para atender às suas necessidades específicas, o .NET Reflector economiza tempo e simplifica o desenvolvimento. Veja a seguir a variedade de recursos de engenharia reversa que essa ferramenta oferece:

- Mostra como os dados fluem por uma biblioteca ou componente
- Oferece informações sobre a implementação e o uso de linguagens e frameworks .NET
- Encontra funcionalidades não documentadas e não expostas para aproveitar melhor as APIs e tecnologias utilizadas.
- Encontra dependências e diferentes assemblies
- Localiza exatamente os erros no seu código, em componentes de terceiros e em bibliotecas.
- Depura o código-fonte de todo o código .NET com o qual você trabalha.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin do ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): você pode usá-lo em qualquer sistema operacional (é possível instalá-lo diretamente pelo VSCode, sem precisar baixar o git. Clique em **Extensions** e **pesquise ILSpy**).\
Se precisar **descompilar**, **modificar** e **recompilar**, você pode usar o [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ou um fork mantido ativamente, o [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clique com o botão direito -> Modify Method** para alterar algo dentro de uma função).

### Inspeção de código gerenciado sem execução com REA

O **REA** pode inspecionar metadados PE/CLI e CIL sem carregar o assembly. Comece pela identidade do artefato e, em seguida, inspecione os membros e os limites nativos declarados; isso é útil ao analisar chamadas suspeitas antes de usar um descompilador ou executar o programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Para comparar versões, `compare_managed_members` usa a identidade bruta de CIL/assinatura e fingerprints de instruções decodificadas, em vez de tratar tokens de metadados como estáveis entre builds. Uma declaração P/Invoke não prova que o código nativo foi executado; `verify_managed_native_boundaries` precisa de uma exportação nativa correspondente ou de Evidence de função para verificar esse limite. Mantenha o digest do artefato, o MVID e os mapeamentos não resolvidos junto com o resultado.<sup>[[17]](#references)</sup>

### DNSpy Logging

Para fazer o **DNSpy registrar algumas informações em um arquivo**, você pode usar este snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuração do DNSpy

Para depurar código usando o DNSpy, você precisa:

Primeiro, altere os **atributos do Assembly** relacionados à **depuração**:

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

E clique em **compilar**:

![DNSpy Logging - DNSpy Debugging: E clique em compilar](<../../images/image (314) (1).png>)

Em seguida, salve o novo arquivo em _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Em seguida, salve o novo arquivo em File Save module](<../../images/image (602).png>)

Isso é necessário porque, se você não fizer isso, várias **otimizações** serão aplicadas ao código em **runtime**, e pode acontecer de um **breakpoint nunca ser atingido** durante a depuração ou de algumas **variáveis não existirem**.

Então, se sua aplicação .NET estiver sendo **executada** pelo **IIS**, você pode **reiniciá-la** com:

```
iisreset /noforce
```

Então, para começar a depuração, feche todos os arquivos abertos e, na **Debug Tab**, selecione **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Então, para começar a depuração, feche todos os arquivos abertos e, na guia Debug, selecione Attach to Process](<../../images/image (318).png>)

Em seguida, selecione **w3wp.exe** para anexá-lo ao **servidor IIS** e clique em **attach**:

![DNSpy Logging - DNSpy Debugging: Em seguida, selecione w3wp.exe para anexá-lo ao servidor IIS e clique em attach](<../../images/image (113).png>)

Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em _Debug >> Break All_ e, em seguida, clique em _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e, em seguida, clique em Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Agora que estamos depurando o processo, é hora de interrompê-lo e carregar todos os módulos. Primeiro, clique em Debug Break All e, em seguida, clique em Debug Windows Modules](<../../images/image (834).png>)

Clique em qualquer módulo em **Modules** e selecione **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Clique em qualquer módulo em Modules e selecione Open All Modules](<../../images/image (922).png>)

Clique com o botão direito em qualquer módulo em **Assembly Explorer** e clique em **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Clique com o botão direito em qualquer módulo em Assembly Explorer e clique em Sort Assemblies](<../../images/image (339).png>)

## Descompilador Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuração de DLLs

### Usando IDA

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- Selecione o depurador **Windbg**
- Selecione "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecione " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure os **parâmetros** da execução, informando o **caminho da DLL** e a função que deseja chamar:

![Debugging DLLs - Using IDA: Configure os parâmetros da execução, informando o caminho da DLL e a função que deseja chamar](<../../images/image (704).png>)

Então, ao iniciar a depuração, **a execução será interrompida quando cada DLL for carregada**. Assim, quando o rundll32 carregar sua DLL, a execução será interrompida.

Esse método interrompe a execução em eventos de carregamento de módulos, mas chegar ao ponto de entrada da DLL carregada é menos direto do que no fluxo de trabalho com x64dbg abaixo.

### Usando x64dbg/x32dbg

- **Carregue o rundll32** (64 bits em C:\Windows\System32\rundll32.exe e 32 bits em C:\Windows\SysWOW64\rundll32.exe)
- **Altere a linha de comando** ( _File --> Change Command Line_ ) e informe o caminho da DLL e a função que deseja chamar, por exemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Altere _Options --> Settings_ e selecione "**DLL Entry**".
- Em seguida, **inicie a execução**. O depurador será interrompido na função main de cada DLL e, em algum momento, você **será interrompido na entrada da sua DLL**. A partir daí, basta procurar os pontos onde deseja definir um breakpoint.

Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver **em qual código está** olhando para o **topo da janela do win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Observe que, quando a execução é interrompida por qualquer motivo no win64dbg, você pode ver em qual código está olhando para o topo da janela do win64dbg](<../../images/image (842).png>)

Esse indicador confirma quando a execução foi interrompida dentro da DLL que você deseja depurar.

## Aplicativos GUI / videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são armazenados na memória de um jogo em execução e alterá-los. Mais informações em:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) é uma ferramenta de front-end/engenharia reversa para o GNU Project Debugger (GDB), voltada para jogos. No entanto, pode ser usada para qualquer atividade relacionada à engenharia reversa.

[**Decompiler Explorer**](https://dogbolt.org/) é um front-end web para vários decompiladores. Esse serviço web permite comparar a saída de diferentes decompiladores em executáveis pequenos.

## Investigação nativa baseada em evidências com REA

**REA** disponibiliza análises do Hopper, Ghidra e IDA por meio de CLI e MCP. Requer Node.js 22.x (no mínimo 22.19), 24.x (no mínimo 24.11) ou 26+, além de npm. Primeiro, configure um provedor nativo existente; verifique `rea providers --json` e selecione um provedor explicitamente se mais de um for compatível com o alvo. No lugar de `0x1000` abaixo, use o nome ou endereço de uma função observado no inventário.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Comece por uma string de recurso ou símbolo, siga as referências e os chamadores e, em seguida, inspecione o dossiê e o pseudocódigo da função selecionada com `rea decompile`. A REA vincula uma sessão ao provider selecionado, em vez de substituí-lo silenciosamente após uma falha. Para consultas reproduzíveis, `--snapshot PATH` reutiliza apenas bytes de artefatos, provider, configurações, operação e parâmetros correspondentes; um snapshot é um cache local, não um banco de dados salvo do provider. Preserve o Evidence retornado e as incógnitas explícitas, em vez de tratar caminhos inferidos ou texto do decompiler como código-fonte original.<sup>[[16]](#references)[[18]](#references)</sup>

Para pontos de entrada de JavaScript/Electron que levam a add-ons nativos, consulte [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Análise com scripts de IDA e Ghidra usando uma ponte TCP local

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) é executado em um banco de dados do IDA ou programa CodeBrowser do Ghidra **já aberto** e permite que um script separado consulte e modifique esse banco de dados de análise. Execute `ID_Server.py` no Python CLI do IDA (`import ID_Server`) ou `Ghidra_Server.py` no Script Manager do Ghidra. O IDA se vincula a `127.0.0.1`, começando pela porta `5073`, e verifica as portas seguintes. O script atual do Ghidra começa na porta `5093` e tenta dez portas até `5102`; seu socket Java se vincula ao endereço curinga, não apenas ao loopback. Verifique a porta exibida pela instância antes de se conectar. Diferentemente de um analisador headless, essa ponte opera no programa atualmente aberto naquela instância da GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Envie **um comando terminado em nova linha por conexão** e leia a resposta terminada em nova linha. Normalmente, o resultado é JSON. Por exemplo, após encontrar uma API importada relevante para um caminho de entrada, `IMPORTXREF` encontra os locais de chamada; em seguida, `DECOMP_XREF` decompila em lote os chamadores de um endereço selecionado. `FUNC` inspeciona uma função, enquanto `PCODE` retorna a representação intermediária do decompiler. Use o endereço do banco de dados ativo, não um endereço copiado de um binário com uma base de relocação diferente. O exemplo abaixo usa a porta padrão do IDA; para o Ghidra, use a porta exibida pelo script.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

O mesmo canal pode **alterar o banco de dados de análise**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` e `PATCH` alteram nomes, tipos, definições de estruturas, limites de funções ou bytes armazenados. `PATCH` é uma edição no banco de dados, **não** uma evidência de patch em um processo ativo. Nenhum dos listeners documenta autenticação. O IDA aceita conexões apenas pelo loopback, mas o Ghidra pode estar acessível pelas interfaces de rede; restrinja o acesso ao listener do Ghidra ao usá-lo. `QUIT` interrompe qualquer um dos listeners, e o IDA também expõe `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando um shellcode com blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) aloca o **shellcode**, exibe seu **endereço de memória** e pausa a execução.\
Conecte um debugger, como o IDA ou o x64dbg, defina um breakpoint no endereço exibido e retome a execução para depurar o shellcode.

A página de releases do GitHub contém arquivos zip com as versões compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Você pode encontrar uma versão ligeiramente modificada do Blobrunner no link a seguir. Para compilá-la, basta **criar um projeto C/C++ no Visual Studio Code, copiar e colar o código e compilá-lo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando um shellcode com jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) é semelhante ao BlobRunner. Ele aloca o shellcode e entra em um loop infinito. Conecte o debugger, retome a execução por **2–5 segundos**, pause dentro desse loop e avance até a chamada seguinte, que transfere a execução para o shellcode alocado.

![Debugger pausado no loop infinito do jmp2it, imediatamente antes da chamada ao shellcode alocado](<../../images/image (509).png>)

Você pode baixar uma versão compilada do [jmp2it na página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) é a interface gráfica do radare. Com o Cutter, você pode emular o shellcode e inspecioná-lo dinamicamente.

Observe que o Cutter permite usar "Open File" e "Open Shellcode". No meu caso, quando abri o shellcode como um arquivo, ele o descompilou corretamente, mas, quando o abri como shellcode, não:

![Cutter exibindo resultados de análise diferentes ao abrir os mesmos bytes como arquivo ou como shellcode](<../../images/image (562).png>)

Para iniciar a emulação no local desejado, defina um bp ali e, aparentemente, o Cutter iniciará automaticamente a emulação a partir desse ponto:

![Definição de um breakpoint na entrada desejada do shellcode antes de iniciar a emulação do Cutter](<../../images/image (589).png>)

![Emulador do Cutter pausado no breakpoint selecionado do shellcode](<../../images/image (387).png>)

Você pode, por exemplo, ver a stack em um despejo hexadecimal:

![Visualização da stack do shellcode emulado no despejo hexadecimal do Cutter](<../../images/image (186).png>)

### Desofuscando shellcode e obtendo as funções executadas

Você pode experimentar o [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ele informa, por exemplo, **quais funções** o shellcode está usando e se ele está se **decodificando** na memória.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg também dispõe de um iniciador gráfico no qual você pode selecionar as opções desejadas e executar o shellcode

![Iniciador gráfico do scDbg para selecionar opções de emulação e rastreamento de shellcode](<../../images/image (258).png>)

A opção **Create Dump** despeja o shellcode final se alguma alteração for feita dinamicamente no shellcode na memória (útil para baixar o shellcode decodificado). O **start offset** pode ser útil para iniciar o shellcode em um deslocamento específico. A opção **Debug Shell** é útil para depurar o shellcode usando o terminal do scDbg (no entanto, considero que qualquer uma das opções explicadas anteriormente é melhor para isso, pois você poderá usar o Ida ou o x64dbg).

### Desmontagem usando o CyberChef

Carregue seu arquivo de shellcode como entrada e use a seguinte receita para desmontá-lo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscação de ofuscação MBA

A ofuscação **Mixed Boolean-Arithmetic (MBA)** oculta expressões simples, como `x + y`, usando fórmulas que combinam operações aritméticas (`+`, `-`, `*`) e operadores bit a bit (`&`, `|`, `^`, `~`, shifts). O importante é que essas identidades geralmente só são corretas sob **aritmética modular de largura fixa**, portanto, os carries e os overflows são importantes:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se você simplificar esse tipo de expressão com ferramentas genéricas de álgebra, pode facilmente obter um resultado incorreto porque a semântica da largura de bits foi ignorada.<sup>[[1]](#references)</sup>

### Fluxo de trabalho prático

1. **Mantenha a largura de bits original** da saída do código/IR/decompilador levantado (`8/16/32/64` bits).
2. **Classifique a expressão** antes de tentar simplificá-la:
   - **Linear**: somas ponderadas de átomos bit a bit
   - **Semilinear**: linear mais máscaras constantes, como `x & 0xFF`
   - **Polinomial**: há produtos
   - **Mista**: produtos e lógica bit a bit estão intercalados, geralmente com subexpressões repetidas
3. **Verifique cada reescrita candidata** com testes aleatórios ou uma prova SMT. Se não for possível provar a equivalência, mantenha a expressão original em vez de tentar adivinhar.

### Contorne o fluxo de controle achatado com uma fatia de execução estreita

Muitas vezes, não é necessário recuperar o grafo de fluxo de controle completo. Em casos de flattening de fluxo de controle, opaque predicates, grandes dispatchers ou código com muitos MBA, siga as referências de blobs criptografados e buffers de saída até a menor rotina que os transforma. Em seguida, reproduza apenas essa fatia do fluxo de dados ou execute-a de forma independente; o dispatcher não faz parte da solução necessária se o estado relevante puder ser inicializado diretamente.<sup>[[7]](#references)</sup>

Um fluxo de trabalho prático é:<sup>[[7]](#references)</sup>

1. Faça o inventário das seções executáveis e de dados, das relocations e das referências cruzadas. Despeje tabelas candidatas de `.rodata`, preservando a ordem dos bytes e a largura dos elementos.
2. Identifique a última rotina que grava o texto em claro ou o buffer de saída. Registre suas entradas, tabelas referenciadas, chamadas importadas e estado global necessário.
3. Levante apenas essas operações em um modelo Python de largura fixa. Se a fatia ainda depender de estado demais, invoque a rotina com Unicorn, QEMU ou um debugger e use hooks para imports irrelevantes, em vez de emular o programa inteiro.
4. Valide se o extractor realmente deriva sua saída do binário fornecido: remova fallbacks silenciosos, procure respostas embutidas nele e execute-o em builds não vistos, com strings, chaves, identificadores, layouts e seeds de obfuscation alterados.

Comandos úteis para uma primeira análise:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expressões MBA que disfarçam constantes

Uma expressão de byte aparentemente dependente da entrada pode cancelar completamente essa entrada. Após extrair suas tabelas, avalie a expressão em todo o domínio de 8 bits; um conjunto de saída unitário prova que esse byte é constante, sem precisar recuperar a máquina de estados circundante.<sup>[[7]](#references)</sup>

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

Mantenha a máscara final, pois a soma original sofre wraparound na largura de um byte. Para um domínio mais amplo, pergunte a um solver SMT se `f(x1) != f(x2)` é satisfatível para duas entradas simbólicas da mesma largura: `unsat` prova a invariância, enquanto `sat` fornece um contraexemplo e significa que a entrada não pode ser descartada.<sup>[[7]](#references)</sup>

#### Reconhecer decodificação vinculada ao ambiente

As verificações anti-análise não precisam desviar o fluxo nem causar uma falha. Um decodificador pode misturar o resultado de um sensor em um bit da chave, em uma constante de predicado opaco ou no estado de um dispatcher achatado, continuar normalmente e produzir texto simples plausível, porém falso, em um emulador. Portanto, corrigir apenas os ramos de falha visíveis não é suficiente; rastreie as dependências de dados das sondas do ambiente até o estado do decodificador, compare o mesmo trecho no dispositivo autêntico e no emulador e teste como forçar cada resultado do sensor altera o buffer final.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) é um simplificador prático de MBA para análise de malware e engenharia reversa de binários protegidos. Ele classifica a expressão e a direciona por pipelines especializados, em vez de aplicar uma única passagem genérica de reescrita a tudo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA avalia a expressão com entradas booleanas, deriva uma assinatura e coloca vários métodos de recuperação em competição, como pattern matching, conversão para ANF e interpolação de coeficientes.
- **Semilinear MBA**: átomos mascarados por constantes são reconstruídos com uma reconstrução particionada por bits, para que as regiões mascaradas permaneçam corretas.
- **Polynomial/Mixed MBA**: os produtos são decompostos em núcleos, e subexpressões repetidas podem ser elevadas a temporários antes de simplificar a relação externa.

Exemplo de uma identidade mista que geralmente vale a pena tentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Isso pode ser reduzido a:

```c
x * y
```

### Notas de reversing

- Prefira executar o CoBRA em **expressões IR levantadas** ou na saída do decompiler, depois de isolar o cálculo exato.
- Use `--bitwidth` explicitamente quando a expressão vier de aritmética com máscara ou de registradores estreitos.
- Se precisar de uma etapa de prova mais robusta, consulte as notas locais sobre Z3 aqui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- O CoBRA também vem como um **plugin de pass do LLVM** (`libCobraPass.so`), útil quando você quer normalizar LLVM IR com muito MBA antes de etapas posteriores de análise.
- Resíduos de domínio misto sensíveis ao carry e não suportados devem ser tratados como um sinal para manter a expressão original e analisar manualmente o caminho do carry.

## Recuperando o flattening de fluxo de controle com estado XOR

Um flattener no estilo OLLVM pode manter o estado do bloco básico atual em dois registradores de 64 bits e reconstruí-lo com XOR em um dispatcher. Cada bloco original grava o par correspondente ao próximo estado e salta de volta para o dispatcher. Um bloco condicional pode usar `CMOVcc` para substituir uma metade do par de acordo com as flags da CPU; por isso, seguir apenas as instruções de desvio visíveis faz com que um dos sucessores passe despercebido. Diferentemente de um dispatcher de salto indireto, essa estrutura pode usar back-edges diretos em todo o fluxo.<sup>[[19]](#references)[[20]](#references)</sup>

Para recuperar o grafo, identifique a árvore de comparação do dispatcher e os dois registradores de estado; mapeie cada estado XOR comparado para o bloco de destino correspondente; em seguida, rastreie as escritas que alcançam o par de registradores em cada bloco original. Para escritas condicionais, inclua a instrução que define as flags e os dois resultados de `CMOVcc`. Reescreva a saída do dispatcher de cada bloco como seu sucessor direto resolvido ou como um desvio condicional; assim, o dispatcher se torna inalcançável sem precisar corrigir o binário. Essa é uma abordagem de CFG completo; se apenas um decoder importar, o [fluxo de trabalho de fatia de execução restrita](#bypass-flattened-control-flow-with-a-narrow-execution-slice) acima pode ser mais rápido.<sup>[[19]](#references)[[20]](#references)</sup>

O [DispatchThis](https://github.com/YungBinary/DispatchThis) automatiza essa estrutura no Binary Ninja. Copie `plugins/DispatchThis` para o diretório de plugins do usuário do Binary Ninja e reinicie o programa. Na função afetada, abra **Function Settings** e selecione `OLLVM_XOR_64`; se a análise não iniciar, use **Analysis → Reanalyze All Functions**. Esse modo reescreve as arestas de fluxo de controle do MLIL, não os bytes do arquivo, e não precisa do Z3 nem do resolvedor de salto indireto. Foi testado no Binary Ninja 5.3.9757+; não remove as escritas de estado mortas por bloco, então não as confunda com transições ativas restantes.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Esse ofuscador substitui operações do programa por sequências de instruções baseadas em `mov` e usa tratamento de sinais/exceções para alterar o fluxo de controle. Para mais detalhes:

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

![Encontrando um ponto de entrada Rust no Ghidra pesquisando nomes de funções por double-colon main](<../../images/image (1080).png>)

Neste caso, o binário se chamava authenticator, então é bastante óbvio que esta é a função main interessante.\
Tendo o **nome** das **funções** chamadas, pesquise por elas na **Internet** para saber mais sobre suas **entradas** e **saídas**.

### Recuperando strings Rust de firmware ELF

Em binários **ELF Rust**, muitas strings estáticas não são referenciadas como ponteiros terminados em NUL no estilo C. Um layout comum do `rustc` é uma **tupla de ponteiro/comprimento** dentro de **`.data.rel.ro`**, apontando para o blob real da string armazenado em **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Isso significa que `strings` ou a análise padrão do Ghidra podem mesclar strings adjacentes ou não detectar referências cruzadas.<sup>[[3]](#references)</sup>

Fluxo de trabalho rápido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Obtenha o endereço virtual e o tamanho de **`.rodata`**.
2. Enumere **`.data.rel.ro`** uma palavra por vez.
3. Trate qualquer valor dentro do intervalo de endereços de `.rodata` como um ponteiro para string candidato.
4. Trate a próxima palavra como o comprimento candidato.
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

Isso é especialmente útil em reversing de firmware, pois as strings Rust recuperadas geralmente revelam **rotas HTTP, nomes de RPC, mensagens de log, assertions, nomes de arquivos, chaves de configuração, handlers de comandos e lógica relacionada à autenticação**.

Se o Ghidra não encontrar essas strings, execute um script/plugin personalizado que aplique a mesma heurística e crie dados de string nos offsets referenciados de `.rodata`. As ferramentas publicadas `rust-strings` e `RustStrings.py`, da Pen Test Partners, são boas referências para adaptar a ideia a outros **tamanhos de palavra, endianness e layouts de seções**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binários compilados com Delphi, você pode usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se você precisar fazer reversing de um binário Delphi, sugiro usar o plugin do IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Esse plugin executará o binário e resolverá os nomes das funções dinamicamente no início da depuração. Após iniciar a depuração, pressione novamente o botão Start (o verde ou f9) e um breakpoint será atingido no início do código real.

Se você pressionar um botão no aplicativo gráfico, o debugger poderá parar na função chamada por esse botão.

## Golang

Para binários Go comuns, o [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) pode recuperar estruturas de runtime e melhorar os nomes das funções no IDA. Carregue o plugin Python com **Alt+F7**.

Se você precisar fazer reversing de um binário Golang, sugiro usar o plugin do IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pressione **Alt+F7** no IDA para carregar um plugin Python e, em seguida, selecione o arquivo do plugin.

Isso resolverá os nomes das funções.

### Recuperar metadados sem a tabela de símbolos

Um executável Go stripped ainda precisa dos metadados de runtime para mapear contadores de programa para funções. O [GoReSym](https://github.com/mandiant/GoReSym) localiza e analisa estruturas como `pclntab` e `moduledata` usando código derivado do runtime do Go. Isso pode recuperar limites de funções, nomes, caminhos de origem, tipos e detalhes do build sem depender da tabela de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Um ofuscador pode deixar essas estruturas utilizáveis enquanto substitui os nomes recuperados. O Garble, por exemplo, aplica hash a identificadores e caminhos de pacotes e remove informações de build, módulos e debug.<sup>[[12]](#references)</sup> O token de pacote ofuscado precisa permanecer consistente entre as funções desse pacote. Agrupe as funções pelo token repetido, infira um pacote com base em suas funções chamadas, strings e APIs e, em seguida, propague esse rótulo de pacote para todo o grupo.<sup>[[13]](#references)</sup>

### Recuperar nomes do Garble com GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina a extração de símbolos do runtime com a geração de referências limpas e a correspondência de grafos de fluxo de controle (CFG). Use esta sequência:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifique a versão do compilador.** Primeiro, tente usar `BuildInfo` e as strings de versão incorporadas. Se o ofuscador as tiver removido, compare partes do runtime Go incluído com runtimes de referência versionados. Nos testes da Volexity, cerca de `2%` do runtime foi suficiente para distinguir as principais versões do Go. Considere isso uma otimização empírica, não um limite universal.<sup>[[13]](#references)</sup>
2. **Crie referências correspondentes.** Gere binários limpos para a versão identificada do Go, a arquitetura de destino e as bibliotecas prováveis. A correspondência do toolchain reduz as diferenças de CFG geradas pelo compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compare as funções.** O GoGrapher compara CFGs de funções e emite pontuações normalizadas de `0.0` a `1.0`. A correspondência de blocos básicos baseia-se em uma comparação ponderada de instruções semelhantes. Correspondências de alta confiança mapeiam funções com nomes aleatorizados para a implementação limpa. Correspondências mais fracas ainda podem identificar um pacote ou módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valide e importe.** Confirme os nomes propostos com relações de chamadas, constantes, strings e efeitos colaterais; em seguida, importe o relatório JSON usando o plugin GoResolver para IDA ou Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instale o toolchain e execute o extrator e comparador de grafos combinados:<sup>[[10]](#references)</sup>

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

O limite padrão de correspondência significativa é `0.9`. As opções `--extract` e `--graph` podem isolar cada etapa, enquanto a execução padrão executa ambas, pois os metadados de runtime recuperados e as evidências do CFG se complementam.<sup>[[10]](#references)</sup> As pontuações do CFG são heurísticas: inlining, build flags, arquitetura e diferenças entre versões de bibliotecas podem alterar a estrutura do grafo; portanto, mantenha as funções não resolvidas em vez de forçar nomes com baixa confiança.<sup>[[13]](#references)</sup>

### Recuperando a tabela de strings do Go

Os binários Go colocam os bytes das strings de todos os pacotes vinculados em uma única tabela contígua. As entradas não são terminadas em NUL e as estruturas de runtime não expõem a base nem o tamanho da tabela. No entanto, o compilador ordena as entradas primeiro por tamanho e depois alfabeticamente, em diferentes sistemas operacionais e arquiteturas. Portanto, depois de encontrar uma entrada, um analista pode percorrer as entradas adjacentes e usar referências cruzadas de dados para associar strings ao código.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatiza esse fluxo de trabalho no IDA Pro e no Ghidra. Aguarde a conclusão da análise automática, pois o plugin depende de referências cruzadas do segmento de dados. A âncora padrão é a string de runtime `entersyscall`; a partir dela, a ferramenta pode examinar em qualquer direção, definir as strings recuperadas no banco de dados e exportar um mapeamento JSON de strings para funções que as referenciam.<sup>[[14]](#references)</sup>

Filtre o relatório pelo pacote da função que referencia as strings para separar o código do aplicativo ou do malware do ruído das bibliotecas vinculadas. Essa técnica não recupera literais destruídos por ofuscação, como a transformação `-literals` do Garble. Ainda assim, ela pode organizar as strings de runtime que não foram ofuscadas.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperando tipos de runtime do Go

O Go incorpora informações de tipos de runtime usadas por recursos como a coleta de lixo. Quando as informações de build são removidas ou o disassembler não analisa esses metadados, as instruções podem parecer carregar endereços de dados arbitrários, e a região de destino permanece sem tipo. Recuperar os metadados transforma esses endereços em referências de tipos legíveis e facilita entender os recursos dos pacotes.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) pode extrair símbolos e analisar tipos de runtime para gerar um relatório JSON. A CLI atual usa o subcomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

A opção `-y`/`--types` ativa a análise de tipos. Importe o relatório usando o plugin do GoResolver para IDA Pro ou Ghidra para definir os tipos recuperados e aplicar suas referências no banco de dados da análise. No formato de relatório introduzido com esse recurso, omitir `-y` deixa os membros de endereço RTTI e de tipos recuperados como null.<sup>[[10]](#references)[[15]](#references)</sup>

O GoResolver oferece suporte a amostras PE, ELF e Mach-O para x86, AMD64, ARM e ARM64, então o mesmo fluxo de trabalho se aplica a binários Go de Windows, Linux e macOS.<sup>[[10]](#references)</sup>

## Python compilado

Nesta página, você pode ver como obter o código Python de um binário ELF/EXE compilado em Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se você obtiver o **binário** de um jogo de GBA, poderá usar diferentes ferramentas para **emulá-lo** e **depurá-lo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Baixe a versão de depuração_) - Inclui um debugger com interface
- [**mgba** ](https://mgba.io)- Inclui um debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin do Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin do Ghidra

No [**no$gba**](https://problemkaputt.de/gba.htm), em _**Options --> Emulation Setup --> Controls**_** ** você pode ver como pressionar os **botões** do Game Boy Advance

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

![Visualização do Ghidra de um binário GBA que faz referência a KEYINPUT no endereço 0x4000130](<../../images/image (447).png>)

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

O último if verifica se **`uVar4`** está na lista anterior de Keys e não é a tecla atual, o que também é chamado de soltar um botão (a tecla atual está armazenada em **`uVar1`**).

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
- Em seguida, o valor é comparado com **8** (o botão **START**); neste desafio, esse caminho verifica se o código inserido é válido.
  - Neste caso, a var **`DAT_030000d8`** é comparada com 0xf3 e, se o valor for igual, algum código é executado.
- Em todos os outros casos, um contador (`DAT_030000d4`) é verificado e incrementado.\
  Enquanto o contador for menor que 8, os valores das teclas pressionadas são acumulados em `DAT_030000d8`.

Assim, neste desafio, sabendo os valores dos botões, era preciso **pressionar uma combinação com menos de 8 teclas cuja soma resultasse em 0xf3.**

**Referência para este tutorial:** [artigo arquivado sobre o desafio Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscação de binários)

## References

- [1] [Simplificando a ofuscação MBA com CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositório CoBRA da Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificando strings Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (arquivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Derrotando a engenharia reversa assistida por IA, ou pelo menos tentando](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Uma abordagem para comparar grafos de fluxo de controle com base na correspondência de blocos básicos](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repositório GoResolver da Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mecanismo de ofuscação Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: usando similaridade de grafos de fluxo de controle para desofuscar automaticamente binários Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repositório GoStringExtractor da Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: atualizações das ferramentas Golang da Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: faça engenharia reversa de qualquer coisa](https://github.com/morluto/rea)
- [17] [Análise de código gerenciado do REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guia da CLI e das evidências do REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: fluxo de trabalho para desfazer o flattening do fluxo de controle no Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: intrusão de dia zero no PaperCut MF, Java Loader, Web Shell e AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README do IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementação do servidor bridge do IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementação do servidor bridge do Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) associa-se ao endereço curinga](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
