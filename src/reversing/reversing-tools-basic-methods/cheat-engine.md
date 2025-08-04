# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos dentro da memória de um jogo em execução e alterá-los.\
Quando você o baixa e executa, é **apresentado** a um **tutorial** de como usar a ferramenta. Se você quiser aprender a usar a ferramenta, é altamente recomendável completá-lo.

## O que você está procurando?

![](<../../images/image (762).png>)

Esta ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente, números** são armazenados em **4bytes**, mas você também pode encontrá-los em formatos **double** ou **float**, ou pode querer procurar algo **diferente de um número**. Por essa razão, você precisa ter certeza de que **seleciona** o que deseja **procurar**:

![](<../../images/image (324).png>)

Você também pode indicar **diferentes** tipos de **buscas**:

![](<../../images/image (311).png>)

Você também pode marcar a caixa para **parar o jogo enquanto escaneia a memória**:

![](<../../images/image (1052).png>)

### Teclas de atalho

Em _**Editar --> Configurações --> Teclas de atalho**_ você pode definir diferentes **teclas de atalho** para diferentes propósitos, como **parar** o **jogo** (o que é bastante útil se em algum momento você quiser escanear a memória). Outras opções estão disponíveis:

![](<../../images/image (864).png>)

## Modificando o valor

Uma vez que você **encontrou** onde está o **valor** que está **procurando** (mais sobre isso nos próximos passos), você pode **modificá-lo** clicando duas vezes nele e, em seguida, clicando duas vezes em seu valor:

![](<../../images/image (563).png>)

E finalmente **marcando a caixa** para que a modificação seja feita na memória:

![](<../../images/image (385).png>)

A **mudança** na **memória** será imediatamente **aplicada** (note que até o jogo não usar esse valor novamente, o valor **não será atualizado no jogo**).

## Buscando o valor

Então, vamos supor que há um valor importante (como a vida do seu usuário) que você deseja melhorar, e você está procurando por esse valor na memória.

### Através de uma mudança conhecida

Supondo que você está procurando o valor 100, você **realiza um escaneamento** buscando por esse valor e encontra muitas coincidências:

![](<../../images/image (108).png>)

Então, você faz algo para que **o valor mude**, e você **para** o jogo e **realiza** um **próximo escaneamento**:

![](<../../images/image (684).png>)

Cheat Engine irá procurar pelos **valores** que **foram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando, agora você pode modificá-lo.\
_Se você ainda tiver vários valores, faça algo para modificar novamente esse valor e realize outro "próximo escaneamento" para filtrar os endereços._

### Valor desconhecido, mudança conhecida

No cenário em que você **não sabe o valor**, mas sabe **como fazê-lo mudar** (e até mesmo o valor da mudança), você pode procurar seu número.

Então, comece realizando um escaneamento do tipo "**Valor inicial desconhecido**":

![](<../../images/image (890).png>)

Em seguida, faça o valor mudar, indique **como** o **valor** **mudou** (no meu caso, foi diminuído em 1) e realize um **próximo escaneamento**:

![](<../../images/image (371).png>)

Você será apresentado a **todos os valores que foram modificados da maneira selecionada**:

![](<../../images/image (569).png>)

Uma vez que você tenha encontrado seu valor, você pode modificá-lo.

Note que há uma **grande quantidade de mudanças possíveis** e você pode fazer esses **passos quantas vezes quiser** para filtrar os resultados:

![](<../../images/image (574).png>)

### Endereço de memória aleatório - Encontrando o código

Até agora, aprendemos como encontrar um endereço que armazena um valor, mas é altamente provável que em **diferentes execuções do jogo, esse endereço esteja em lugares diferentes da memória**. Então, vamos descobrir como sempre encontrar esse endereço.

Usando alguns dos truques mencionados, encontre o endereço onde seu jogo atual está armazenando o valor importante. Então (parando o jogo se desejar), clique com o botão direito no **endereço** encontrado e selecione "**Descobrir o que acessa este endereço**" ou "**Descobrir o que escreve neste endereço**":

![](<../../images/image (1067).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** esse **endereço** (o que é útil para mais coisas, como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica** e será mais útil neste caso, pois estamos interessados em saber **de onde esse valor está sendo escrito**.

Uma vez que você tenha selecionado uma dessas opções, o **debugger** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** o **jogo** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deve ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![](<../../images/image (91).png>)

Agora que você encontrou o endereço que está modificando o valor, você pode **modificar o código à sua vontade** (Cheat Engine permite que você o modifique para NOPs rapidamente):

![](<../../images/image (1057).png>)

Assim, você pode agora modificá-lo para que o código não afete seu número, ou sempre afete de uma maneira positiva.

### Endereço de memória aleatório - Encontrando o ponteiro

Seguindo os passos anteriores, encontre onde o valor que você está interessado está. Então, usando "**Descobrir o que escreve neste endereço**", descubra qual endereço escreve esse valor e clique duas vezes nele para obter a visualização da desassemblagem:

![](<../../images/image (1039).png>)

Em seguida, realize um novo escaneamento **buscando o valor hex entre "\[]"** (o valor de $edx neste caso):

![](<../../images/image (994).png>)

(_Se vários aparecerem, você geralmente precisa do menor endereço_)\
Agora, encontramos o **ponteiro que irá modificar o valor que nos interessa**.

Clique em "**Adicionar Endereço Manualmente**":

![](<../../images/image (990).png>)

Agora, clique na caixa de seleção "Ponteiro" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior foi "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Note como o primeiro "Endereço" é automaticamente preenchido a partir do endereço do ponteiro que você introduziu)

Clique em OK e um novo ponteiro será criado:

![](<../../images/image (308).png>)

Agora, toda vez que você modificar esse valor, você estará **modificando o valor importante, mesmo que o endereço de memória onde o valor está seja diferente.**

### Injeção de Código

A injeção de código é uma técnica onde você injeta um pedaço de código no processo alvo e, em seguida, redireciona a execução do código para passar pelo seu próprio código escrito (como te dar pontos em vez de subtraí-los).

Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador:

![](<../../images/image (203).png>)

Clique em Mostrar desassemblador para obter o **código desassemblado**.\
Em seguida, clique **CTRL+a** para invocar a janela de Auto assemble e selecione _**Modelo --> Injeção de Código**_

![](<../../images/image (902).png>)

Preencha o **endereço da instrução que você deseja modificar** (isso geralmente é preenchido automaticamente):

![](<../../images/image (744).png>)

Um modelo será gerado:

![](<../../images/image (944).png>)

Então, insira seu novo código assembly na seção "**newmem**" e remova o código original da seção "**originalcode**" se você não quiser que ele seja executado. Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![](<../../images/image (521).png>)

**Clique em executar e assim seu código deve ser injetado no programa, mudando o comportamento da funcionalidade!**

## Recursos avançados no Cheat Engine 7.x (2023-2025)

Cheat Engine continuou a evoluir desde a versão 7.0 e vários recursos de qualidade de vida e *reversão ofensiva* foram adicionados que são extremamente úteis ao analisar software moderno (e não apenas jogos!). Abaixo está um **guia de campo muito condensado** para as adições que você provavelmente usará durante o trabalho de red-team/CTF.

### Melhorias do Scanner de Ponteiros 2
* `Os ponteiros devem terminar com deslocamentos específicos` e o novo controle deslizante **Desvio** (≥7.4) reduzem muito os falsos positivos quando você rescaneia após uma atualização. Use-o junto com a comparação de multi-mapa (`.PTR` → *Comparar resultados com outro mapa de ponteiro salvo*) para obter um **único ponteiro-base resiliente** em apenas alguns minutos.
* Atalho de filtro em massa: após o primeiro escaneamento, pressione `Ctrl+A → Espaço` para marcar tudo, depois `Ctrl+I` (inverter) para desmarcar endereços que falharam no rescaneamento.

### Ultimap 3 – Rastreio Intel PT
*Desde 7.5, o antigo Ultimap foi reimplementado sobre o **Intel Processor-Trace (IPT)**. Isso significa que agora você pode gravar *cada* ramificação que o alvo toma **sem passo a passo** (apenas em modo de usuário, não acionará a maioria dos gadgets anti-debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Após alguns segundos, pare a captura e **clique com o botão direito → Salvar lista de execução em arquivo**. Combine endereços de ramificação com uma sessão de `Find out what addresses this instruction accesses` para localizar hotspots de lógica de jogo de alta frequência extremamente rápido.

### Modelos de `jmp` / auto-patch de 1 byte
A versão 7.5 introduziu um stub JMP *de um byte* (0xEB) que instala um manipulador SEH e coloca um INT3 na localização original. Ele é gerado automaticamente quando você usa **Auto Assembler → Template → Code Injection** em instruções que não podem ser patchadas com um salto relativo de 5 bytes. Isso torna possíveis ganchos "apertados" dentro de rotinas compactadas ou com restrição de tamanho.

### Stealth em nível de kernel com DBVM (AMD & Intel)
*DBVM* é o hipervisor Tipo-2 embutido do CE. Compilações recentes finalmente adicionaram **suporte AMD-V/SVM** para que você possa executar `Driver → Load DBVM` em hosts Ryzen/EPYC. O DBVM permite que você:
1. Crie breakpoints de hardware invisíveis para verificações de Ring-3/anti-debug.
2. Leia/escreva regiões de memória do kernel pagináveis ou protegidas, mesmo quando o driver em modo usuário está desativado.
3. Realize bypasses de ataque de temporização sem VM-EXIT (por exemplo, consultar `rdtsc` do hipervisor).

**Dica:** O DBVM se recusará a carregar quando HVCI/Memory-Integrity estiver habilitado no Windows 11 → desative-o ou inicialize um host de VM dedicado.

### Depuração remota / multiplataforma com **ceserver**
O CE agora inclui uma reescrita completa do *ceserver* e pode se conectar via TCP a **Linux, Android, macOS & iOS**. Um fork popular integra *Frida* para combinar instrumentação dinâmica com a GUI do CE – ideal quando você precisa patchar jogos Unity ou Unreal rodando em um telefone:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Para a ponte Frida, veja `bb33bb/frida-ceserver` no GitHub.

### Outras novidades notáveis
* **Patch Scanner** (MemView → Tools) – detecta mudanças de código inesperadas em seções executáveis; útil para análise de malware.
* **Structure Dissector 2** – arraste um endereço → `Ctrl+D`, depois *Guess fields* para avaliar automaticamente estruturas C.
* **.NET & Mono Dissector** – suporte melhorado para jogos Unity; chame métodos diretamente do console Lua do CE.
* **Tipos personalizados Big-Endian** – escaneamento/edição de ordem de bytes revertida (útil para emuladores de console e buffers de pacotes de rede).
* **Autosave & tabs** para janelas AutoAssembler/Lua, além de `reassemble()` para reescrita de instruções em várias linhas.

### Notas de instalação e OPSEC (2024-2025)
* O instalador oficial vem com ofertas **ad-offers** do InnoSetup (`RAV`, etc.). **Sempre clique em *Decline*** *ou compile a partir do código-fonte* para evitar PUPs. Os AVs ainda marcarão `cheatengine.exe` como um *HackTool*, o que é esperado.
* Drivers modernos anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detectam a classe de janela do CE mesmo quando renomeada. Execute sua cópia de reversão **dentro de uma VM descartável** ou após desativar o jogo em rede.
* Se você só precisa de acesso em modo de usuário, escolha **`Settings → Extra → Kernel mode debug = off`** para evitar carregar o driver não assinado do CE que pode causar BSOD no Windows 11 24H2 Secure-Boot.

---

## **Referências**

- [Notas de lançamento do Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [ponte cross-platform frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Tutorial do Cheat Engine, complete para aprender como começar com o Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
