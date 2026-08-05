# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são armazenados na memória de um jogo em execução e alterá-los.\
Quando você faz o download e o executa, é **apresentado** a um **tutorial** sobre como usar a ferramenta. Se quiser aprender a usá-la, é altamente recomendável concluí-lo.<sup>[[3]](#references)</sup>

## O que você está procurando?

![Cheat Engine - O que você está procurando?: O que você está procurando?](<../../images/image (762).png>)

Essa ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente, os números** são armazenados no formato de **4bytes**, mas você também pode encontrá-los nos formatos **double** ou **float**, ou talvez queira procurar algo **diferente de um número**. Por esse motivo, você precisa ter certeza de que **selecionou** o que deseja **procurar**:

![Cheat Engine - O que você está procurando?: Geralmente, os números são armazenados no formato 4bytes, mas você também pode encontrá-los nos formatos double ou float, ou talvez queira procurar algo...](<../../images/image (324).png>)

Você também pode indicar **diferentes** tipos de **buscas**:

![Cheat Engine - O que você está procurando?: Você também pode indicar diferentes tipos de buscas](<../../images/image (311).png>)

Você também pode marcar a caixa para **parar o jogo durante a varredura da memória**:

![Cheat Engine - O que você está procurando?: Você também pode marcar a caixa para parar o jogo durante a varredura da memória](<../../images/image (1052).png>)

### Hotkeys

Em _**Edit --> Settings --> Hotkeys**_, você pode definir diferentes **hotkeys** para diferentes finalidades, como **parar** o **jogo** (o que é bastante útil se, em algum momento, você quiser fazer uma varredura da memória). Outras opções estão disponíveis:

![O que você está procurando? - Hotkeys: Em Edit -- Settings -- Hotkeys, você pode definir diferentes hotkeys para diferentes finalidades, como parar o jogo (o que é bastante útil se, em algum momento, você...](<../../images/image (864).png>)

## Modificando o valor

Depois de **encontrar** onde está o **valor** que você está **procurando** (mais informações sobre isso nas etapas a seguir), você pode **modificá-lo** clicando duas vezes nele e, em seguida, clicando duas vezes no valor:

![Hotkeys - Modificando o valor: Depois de encontrar onde está o valor que você está procurando (mais informações sobre isso nas etapas a seguir), você pode modificá-lo clicando duas vezes nele e, em seguida, clicando duas vezes...](<../../images/image (563).png>)

Por fim, **marque a caixa** para efetivar a modificação na memória:

![Hotkeys - Modificando o valor: Por fim, marque a caixa para efetivar a modificação na memória](<../../images/image (385).png>)

A **alteração** na **memória** será **aplicada** imediatamente (observe que, até que o jogo use esse valor novamente, o valor **não será atualizado no jogo**).

## Procurando o valor

Vamos supor que exista um valor importante (como a vida do seu personagem) que você queira aumentar e que esteja procurando esse valor na memória.

### Por meio de uma alteração conhecida

Supondo que você esteja procurando o valor 100, faça uma **varredura** procurando esse valor e encontrará muitas ocorrências:

![Procurando o valor - Por meio de uma alteração conhecida: Supondo que você esteja procurando o valor 100, faça uma varredura procurando esse valor e encontrará muitas ocorrências](<../../images/image (108).png>)

Em seguida, faça algo para que o **valor mude**, **pare** o jogo e faça uma **nova varredura**:

![Procurando o valor - Por meio de uma alteração conhecida: Em seguida, faça algo para que o valor mude, pare o jogo e faça uma nova varredura](<../../images/image (684).png>)

O Cheat Engine procurará os **valores** que **mudaram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando e agora pode modificá-lo.\
_Se ainda houver vários valores, faça algo para modificar esse valor novamente e execute outra "next scan" para filtrar os endereços._

### Valor desconhecido, alteração conhecida

No cenário em que você **não conhece o valor**, mas sabe **como fazê-lo mudar** (e até mesmo o valor da alteração), você pode procurar esse número.

Comece fazendo uma varredura do tipo "**Unknown initial value**":

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Comece fazendo uma varredura do tipo " Unknown initial value "](<../../images/image (890).png>)

Depois, faça o valor mudar, indique **como** o **valor** **mudou** (no meu caso, ele diminuiu em 1) e faça uma **nova varredura**:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Depois, faça o valor mudar, indique como o valor mudou (no meu caso, ele diminuiu em 1) e faça uma nova varredura](<../../images/image (371).png>)

Serão apresentados todos os **valores que foram modificados da maneira selecionada**:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Serão apresentados todos os valores que foram modificados da maneira selecionada](<../../images/image (569).png>)

Depois de encontrar o valor, você poderá modificá-lo.

Observe que existem **muitas alterações possíveis** e que você pode executar estas **etapas quantas vezes quiser** para filtrar os resultados:

![Por meio de uma alteração conhecida - Valor desconhecido, alteração conhecida: Observe que existem muitas alterações possíveis e que você pode executar estas etapas quantas vezes quiser para filtrar os resultados](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Até agora, aprendemos a encontrar um endereço que armazena um valor, mas é muito provável que, em **execuções diferentes do jogo, esse endereço esteja em locais diferentes da memória**. Então, vamos descobrir como sempre encontrar esse endereço.

Usando alguns dos truques mencionados, encontre o endereço onde o jogo atual está armazenando o valor importante. Em seguida (parando o jogo, se desejar), clique com o **botão direito** no **endereço** encontrado e selecione "**Find out what accesses this address**" ou "**Find out what writes to this address**":

![Valor desconhecido, alteração conhecida - Random Memory Address - Finding the code: Usando alguns dos truques mencionados, encontre o endereço onde o jogo atual está armazenando o valor importante. Em seguida...](<../../images/image (1067).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** esse **endereço** (o que é útil para outras coisas, como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica** e será mais útil neste caso, pois estamos interessados em saber **de onde esse valor está sendo gravado**.

Depois de selecionar uma dessas opções, o **debugger** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deverá ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![Valor desconhecido, alteração conhecida - Random Memory Address - Finding the code: Depois de selecionar uma dessas opções, o debugger será anexado ao programa e uma nova janela vazia...](<../../images/image (91).png>)

Agora que você encontrou o endereço que modifica o valor, pode **modificar o código como preferir** (o Cheat Engine permite modificá-lo rapidamente para usar NOPs):

![Valor desconhecido, alteração conhecida - Random Memory Address - Finding the code: Agora que você encontrou o endereço que modifica o valor, pode modificar o código como preferir (o Cheat Engine...](<../../images/image (1057).png>)

Assim, você pode modificá-lo para que o código não afete seu número ou sempre o afete de maneira positiva.

### Random Memory Address - Finding the pointer

Seguindo as etapas anteriores, encontre onde está o valor de seu interesse. Em seguida, usando "**Find out what writes to this address**", descubra qual endereço grava esse valor e clique duas vezes nele para obter a visualização da disassembly:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Seguindo as etapas anteriores, encontre onde está o valor de seu interesse. Em seguida, usando " Find out...](<../../images/image (1039).png>)

Depois, faça uma nova varredura **procurando o valor hexadecimal entre "\[]"** (o valor de $edx neste caso):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Depois, faça uma nova varredura procurando o valor hexadecimal entre " ()" (o valor de $edx neste caso)](<../../images/image (994).png>)

(_Se aparecerem vários, geralmente você precisa escolher o de menor endereço_)\
Agora, **encontramos o ponteiro que modificará o valor de nosso interesse**.

Clique em "**Add Address Manually**":

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Clique em " Add Address Manually "](<../../images/image (990).png>)

Agora, marque a caixa "Pointer" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior era "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Agora, marque a caixa "Pointer" e adicione o endereço encontrado na caixa de texto (neste cenário,...](<../../images/image (392).png>)

(Observe como o primeiro "Address" é preenchido automaticamente com base no endereço do ponteiro que você inseriu.)

Clique em OK e um novo ponteiro será criado:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Clique em OK e um novo ponteiro será criado](<../../images/image (308).png>)

Agora, sempre que você modificar esse valor, estará **modificando o valor importante, mesmo que o endereço de memória onde ele está seja diferente.**

### Code Injection

Code injection é uma técnica na qual você injeta um trecho de código no processo-alvo e, em seguida, redireciona a execução para passar pelo código que você escreveu (por exemplo, concedendo pontos em vez de removê-los).

Imagine que você encontrou o endereço que subtrai 1 da vida do seu personagem:

![Random Memory Address - Finding the pointer - Code Injection: Imagine que você encontrou o endereço que subtrai 1 da vida do seu personagem](<../../images/image (203).png>)

Clique em Show disassembler para obter o **código disassemblado**.\
Em seguida, pressione **CTRL+a** para abrir a janela Auto assemble e selecione _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Em seguida, pressione CTRL+a para abrir a janela Auto assemble e selecione Template -- Code Injection](<../../images/image (902).png>)

Preencha o **endereço da instrução que deseja modificar** (normalmente, ele é preenchido automaticamente):

![Random Memory Address - Finding the pointer - Code Injection: Preencha o endereço da instrução que deseja modificar (normalmente, ele é preenchido automaticamente)](<../../images/image (744).png>)

Um template será gerado:

![Random Memory Address - Finding the pointer - Code Injection: Um template será gerado](<../../images/image (944).png>)

Insira seu novo código assembly na seção "**newmem**" e remova o código original de "**originalcode**" se não quiser que ele seja executado**.** Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![Random Memory Address - Finding the pointer - Code Injection: Insira seu novo código assembly na seção " newmem " e remova o código original de " originalcode " se não...](<../../images/image (521).png>)

**Clique em execute e assim por diante, e seu código deverá ser injetado no programa, alterando o comportamento da funcionalidade!**

## Recursos avançados do Cheat Engine 7.x (2023-2025)

O Cheat Engine continuou evoluindo desde a versão 7.0, e vários recursos de qualidade de vida e de *offensive-reversing* foram adicionados. Eles são extremamente úteis ao analisar software moderno (e não apenas jogos!). Abaixo está um **guia de campo muito condensado** das adições que você provavelmente mais usará durante trabalhos de red-team/CTF.<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` e o novo controle deslizante **Deviation** (>=7.4) reduzem bastante os falsos positivos ao fazer uma nova varredura após uma atualização. Use-o junto com a comparação de vários mapas (`.PTR` -> *Compare results with other saved pointer map*) para obter um **ponteiro-base resiliente único** em apenas alguns minutos.
* Atalho para filtragem em massa: após a primeira varredura, pressione `Ctrl+A -> Space` para marcar tudo e, em seguida, `Ctrl+I` (inverter) para desmarcar os endereços que falharam na nova varredura.

### Ultimap 3 - Intel PT tracing
*A partir da versão 7.5, o antigo Ultimap foi reimplementado sobre o **Intel Processor-Trace (IPT)**.* Isso significa que agora você pode registrar **cada branch executado pelo alvo** **sem usar single-stepping** (somente em user-mode; isso não acionará a maioria dos mecanismos anti-debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Após alguns segundos, interrompa a captura e faça **clique com o botão direito → Save execution list to file**. Combine os endereços das branches com uma sessão de `Find out what addresses this instruction accesses` para localizar hotspots de lógica do jogo de alta frequência com extrema rapidez.

### Templates de `jmp` de 1 byte / auto-patch
A versão 7.5 introduziu um stub de JMP de *um byte* (0xEB) que instala um handler de SEH e coloca um INT3 no local original. Ele é gerado automaticamente quando você usa **Auto Assembler → Template → Code Injection** em instruções que não podem ser corrigidas com um salto relativo de 5 bytes. Isso possibilita hooks “tight” dentro de rotinas packed ou com restrições de tamanho.

### Stealth em nível de kernel com DBVM (AMD e Intel)
*DBVM* é o hypervisor Type-2 integrado ao CE. As versões recentes finalmente adicionaram **suporte a AMD-V/SVM**, permitindo executar `Driver → Load DBVM` em hosts Ryzen/EPYC. O DBVM permite:
1. Criar hardware breakpoints invisíveis para verificações de Ring-3/anti-debug.
2. Ler/escrever regiões de memória do kernel pageable ou protegidas, mesmo quando o driver em user-mode está desabilitado.
3. Realizar bypasses de timing attacks sem VM-EXIT (por exemplo, consultar `rdtsc` a partir do hypervisor).

**Dica:** o DBVM se recusará a carregar quando HVCI/Memory-Integrity estiver habilitado no Windows 11 → desabilite-o ou inicialize uma VM-host dedicada.

### Debugging remoto / cross-platform com **ceserver**
O CE agora inclui uma reescrita completa do *ceserver* e pode se conectar via TCP a targets **Linux, Android, macOS e iOS**. Um fork popular integra o *Frida* para combinar instrumentação dinâmica com a GUI do CE — ideal quando você precisa fazer patch em jogos Unity ou Unreal executados em um telefone:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Para a bridge do Frida, veja `bb33bb/frida-ceserver` no GitHub.<sup>[[2]](#references)</sup>

### Outros recursos dignos de nota
* **Patch Scanner** (MemView → Tools) – detecta alterações inesperadas no código em seções executáveis; útil para análise de malware.
* **Structure Dissector 2** – arraste um endereço → `Ctrl+D` e selecione *Guess fields* para avaliar automaticamente C-structures.
* **.NET & Mono Dissector** – suporte aprimorado para jogos Unity; chame métodos diretamente pelo console Lua do CE.
* **Big-Endian custom types** – faz scan/edição com a ordem dos bytes invertida (útil para emuladores de consoles e buffers de pacotes de rede).
* **Autosave & tabs** para janelas do AutoAssembler/Lua, além de `reassemble()` para reescrever instruções em várias linhas.

### Notas de instalação e OPSEC (2024-2025)
* O instalador oficial inclui **ad-offers** do InnoSetup (`RAV` etc.). **Sempre clique em *Decline*** *ou compile a partir do código-fonte* para evitar PUPs. Os antivírus ainda sinalizarão `cheatengine.exe` como uma *HackTool*, o que é esperado.
* Drivers modernos de anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detectam a classe da janela do CE mesmo quando ela é renomeada. Execute sua cópia de reversing **dentro de uma VM descartável** ou após desativar o jogo em rede.
* Se você precisa apenas de acesso user-mode, escolha **`Settings → Extra → Kernel mode debug = off`** para evitar carregar o driver não assinado do CE, que pode causar BSOD no Windows 11 24H2 com Secure-Boot.

---

## Referências

- [1] [Notas de lançamento do Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [bridge multiplataforma frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Tutorial do Cheat Engine; conclua-o para aprender a começar a usar o Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
